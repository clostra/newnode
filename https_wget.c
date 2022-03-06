// implementation of g_https_cb callback using wget
//
// Provides a routine that the main program can call from a callback
// passed to newnode_init().
//
// The g_https_cb callback lets the newnode client make an asychronous
// https request.  On completion a completion callback is called, to
// which is passed a boolean success indication if the request was
// successful.  On most platforms the https request is accomplished
// using the normal system library to do that (configured if necessary
// to use NewNode as its http proxy).  But on Linux there is no
// distinguished system library for https.  This implementation uses
// the 'wget' program to do the download.  It won't work if wget is
// not installed.
//
// It's arguable that the default Linux implementation of this should
// not use wget, but instead use something else: maybe libcurl, maybe
// libevent's https stack.  The wget implementation was intended to be
// low effort, something to make sure the rest of the "try first" code
// worked, though it turned out to be a lot of trouble to get working.
//
// The rest of NN must be able to run concurrently while this request
// is being processed, otherwise there will be deadlock when the
// g_https_cb implementation makes CONNECT requests back to NN's web
// proxy.  So the wget program is run in a subprocess, and the exit
// status is examined to see whether the request succeeded (and if not,
// what the error was).
//
// unless otherwise stated, everything in this module must be called
// from the libevent thread

#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <inttypes.h>

#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/http_struct.h>

#include "features.h"
#include "log.h"
#include "network.h"
#include "newnode.h"
#include "g_https_cb.h"
#include "client.h"

#ifndef PATH_WGET
#define PATH_WGET "/usr/bin/wget"
#endif

#define NSUBPROC 50

#define MAX_BUFSIZE (1024 * 1024)

// Maintain a list of currently-active subprocesses, so that when a
// subprocess exits, we can keep track of request parameters, where to
// store the result, what callback to call, etc.
//
// Here are the rules for use of subprocs[] so that we don't need mutexes:
//
// - All calls to alloc_subproc(), free_subproc() or anything that
//   depends on or changes 'flags' or 'request_id' (i.e. things that
//   change allocation of a subproc[] slot) must run in the main
//   libevent thread.
//
// - free_subproc() is only called from the main libevent thread,
//   indirectly by a call to network_async() from
//   child_exit_event_cb(), and only after any completion callback has
//   been called.
//
// - cancel_https_request() must also only be called from the main
//   libevent thread.  cancel_https_request() MUST reliably inhibit
//   calling the completion callback by setting the CANCELLED bit for
//   any https request that has not already completed and called its
//   completion callback.

struct subproc {
    pid_t pid;
    volatile int flags;
#define INUSE 01
#define EXITED 02
#define HASOUTPUTFILE 04
#define CANCELLED 010
    int exit_status;                        // subprocess exit status
    https_complete_callback cb;                // completion callback
    https_request request;                // copy of request passed to g_https_cb()
    char *name;                                // identifying string
    int child_stdout;                        // parent's file descriptor of child's stdout
    char *outputfilename;
    https_result result;                // storage for result passed to completion callback
    volatile int64_t request_id;        // unique ID for request
} subprocs[NSUBPROC];

typedef struct subproc subproc;
int max_subproc = -1;
static int request_serial = 1;

static char *flags(int f)
{
    static char buf[1024];
    snprintf(buf, sizeof(buf), "0x%x <%s%s%s%s>", f,
             f & INUSE ? "INUSE" : "",
             f & EXITED ? ",EXITED" : "",
             f & HASOUTPUTFILE ? ",HASOUTPUTFILE" : "",
             f & CANCELLED ? ",CANCELLED" : "");
    return buf;
}

static struct subproc *alloc_subproc(https_request *req)
{
    int i;
    // allocate first unused subprocess
    for (i = 0; i < NSUBPROC && subprocs[i].flags & INUSE; ++i);
    if (i < NSUBPROC) {
        subprocs[i].flags |= INUSE;
        subprocs[i].request_id = (request_serial++ * NSUBPROC) + i;
        if (req) {
            subprocs[i].request = *req;
        } else {
            // implement defaults if req==NULL
            // (bufsize=0, flags=0, timeout_sec=7)
            memset(&(subprocs[i].request), 0, sizeof(https_request));
            subprocs[i].request.timeout_sec = 7;
        }
        memset(&(subprocs[i].result), 0, sizeof (struct https_result));
        if (req && req->flags & HTTPS_USE_HEAD) {
            subprocs[i].result.result_flags |= HTTPS_REQUEST_USE_HEAD;
        }
        if (req && req->flags & HTTPS_ONE_BYTE) {
            subprocs[i].result.result_flags |= HTTPS_REQUEST_ONE_BYTE;
        }
        subprocs[i].result.request_id = subprocs[i].request_id;
        if (i > max_subproc) {
            max_subproc = i;
            // debug("max_subproc is now %d\n", i);
        }
        return subprocs + i;
    }

    debug("%s: NSUBPROC too small\n", __func__);
    if (o_debug) {
        for (i = 0; i < NSUBPROC; ++i) {
            struct subproc *sp = subprocs + i;
            fprintf(stderr, "subprocs[%d] = { pid:%d, flags:%s, exit_status:%d, request_id:%" PRId64 ", name:%s\n",
                    i, sp->pid, flags(sp->flags), sp->exit_status, sp->request_id, sp->name);
        }
    }
    return NULL;
}

static void free_subproc (struct subproc *sp)
{
    if (!sp) {
        return;
    }
    if ((sp - subprocs) >= 0 && (sp - subprocs) < NSUBPROC) {
        debug("%s request_id:%" PRId64 " flags:%s\n", __func__, sp->request_id, flags(sp->flags));
        sp->flags = 0;
        if (sp->cb) {
            Block_release(sp->cb);
            sp->cb = NULL;
        }
        if (sp->name) {
            free(sp->name);
            sp->name = NULL;
        }
        if (sp->outputfilename) {
            free(sp->outputfilename);
            sp->outputfilename = NULL;
        }
        if (sp->result.response_body) {
            free(sp->result.response_body);
            sp->result.response_body = NULL;
        }
        memset(sp, 0, sizeof(*sp));
        return;
    }
    debug("%s: sp:%p not within range\n", __func__, sp);
    return;
}

static struct subproc *find_subproc(pid_t pid)
{
    int i;

    for (i = 0; i < NSUBPROC; ++i) {            // XXX change < NSUBPROC to <= max_subproc
        if ((subprocs[i].flags & INUSE) && (subprocs[i].pid == pid)) {
            return subprocs + i;
        }
    }
    return NULL;
}

static pid_t spawn(struct subproc *sp, char *program, char **child_argv, int child_stdout, char **env_mods, 
                   off_t maxfsize)
{
    pid_t child_pid;
    int i;
    int envc;
    sigset_t old_set, block_set;

    if (sp == NULL) {
        return (pid_t) -1;
    }

    sigemptyset(&block_set);
    sigaddset(&block_set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &block_set, NULL);
    switch (child_pid = fork()) {
    case 0:                     /* child */
        if (env_mods) {
            for (i = 0; env_mods[i]; ++i) {
                char *equal = strchr(env_mods[i], '=');

                if (equal) {
                    char *name = strndup(env_mods[i], equal-env_mods[i]);
                    char *value = equal + 1;
                    setenv(name, value, 1);
                }
            }
        }
        if (child_stdout > 0) {
            dup2(child_stdout, 1);
        }

        // close all open fd's except for stdin, stdout, stderr
        //
        // it's possible for fds >= FD_SETSIZE to exist, but they
        // could not be used with select().  There seems to be no
        // good/efficient/portable way to determine the max open file
        // descriptor. Why isn't there a syscall to close all FDs (or
        // mark as close-on-exec) other than those specified in a bit
        // mask?
        for (int fd = 3; fd < FD_SETSIZE; ++fd)
            close(fd);
        if (maxfsize) {
            // limit size of output file so that we won't download an
            // arbitrary amount of data.  This seems to work (though
            // not with arbitrary granularity, but that's ok).  It's
            // not yet clear whether it also limits the amount of
            // debugging output, or whether it limits the number of 
            // bytes that can be written to /dev/null.
            //
            // wget has an option to limit output file size, but it
            // didn't work when tested.
            struct rlimit oldrlim, newrlim;
            getrlimit(RLIMIT_FSIZE, &oldrlim);
            newrlim.rlim_cur = MIN((rlim_t) maxfsize, oldrlim.rlim_max);
            newrlim.rlim_max = MIN((rlim_t) maxfsize, oldrlim.rlim_max);
            setrlimit(RLIMIT_FSIZE, &newrlim);
        }
        execv(program, child_argv);
        debug("spawn: pid %d: cannot exec %s: %s\n", getpid(), program, strerror(errno));
        _exit(127);
        break;
    case -1:                    /* error */
        pthread_sigmask(SIG_UNBLOCK, &block_set, NULL);
        return (pid_t) -1;
    default:                    /* parent */
        pthread_sigmask(SIG_UNBLOCK, &block_set, NULL);
        sp->pid = child_pid;
        return child_pid;
    }
}

static off_t fdsize(int fd)
{
    struct stat buf;
    if (fstat (fd, &buf) < 0) {
        return 0;
    }
    return buf.st_size;
}

static void child_exit_event_cb(evutil_socket_t fd, short events, void *arg)
{
    int count;
    struct subproc *sp;
    char buf[20];
    int nread;
    int i;
    extern network *g_n;
    pid_t pid;
    int wstatus;

    debug("%s fd:%d events:%x arg:%p\n", __func__, fd, events, arg);

    // do waitpid processing here since the actual SIGCHLD handler is inside libevent.
    //
    // for every exited process waitpid returns, mark it as EXITED in the subproc table
    while ((pid = waitpid(0, &wstatus, WNOHANG)) > 0) {
        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            if ((sp = find_subproc(pid)) != NULL) {
                sp->flags |= EXITED;
                sp->exit_status = wstatus;
            } else {
                if (WIFEXITED(wstatus)) {
                    debug("!!! cannot find subproc for pid %d which exited with status %d\n", 
                          pid, WEXITSTATUS(wstatus));
                } else {
                    debug("!!! cannot find subproc for pid %d which was killed by signal %d\n", 
                          pid, WTERMSIG(wstatus));
                }
            }
        }
    }

    // for each subprocess tagged as EXITED, call its callback and
    // clean up the subprocess slot
    for (i = 0; i < NSUBPROC; ++i) {            // XXX change < NSUBPROC to <= max_subproc
        sp = subprocs + i;
        struct https_request *request = &(sp->request);
        struct https_result *result = &(sp->result);

        if (sp->flags & EXITED) {
            int64_t request_id = sp->request_id;

            debug("%s sp:%p\n", __func__, sp);
            // Unfortunately wget isn't great at distinguishing
            // different kinds of error that are needed for the try
            // first strategy.  But we try to map wget's exit codes
            // into https_error codes.
            //
            // (from wget man page:)
            //
            // Wget may return one of several error codes if it encounters problems.
            // 0 No problems occurred.
            // 1 Generic error code.
            // 2 Parse error---for instance, when parsing command-line options, the .wgetrc or .netrc
            // 3 File I/O error.
            // 4 Network failure.
            // 5 SSL verification failure.
            // 6 Username/password authentication failure.
            // 7 Protocol errors.
            // 8 Server issued an error response.
            if (WIFEXITED(sp->exit_status)) {
                debug("%s: pid:%d request_id:%" PRId64 " name:%s exited with status %d\n",
                      __func__, sp->pid, sp->request_id, sp->name,
                      WEXITSTATUS(sp->exit_status));

                if (sp->flags & CANCELLED) {
                    debug("%s: exited pid:%d request_id:%" PRId64 " name:%s was already cancelled\n",
                          __func__, sp->pid, sp->request_id, sp->name);
                    free_subproc(sp);
                } else {
                    // set error code if not already set
                    if (result->https_error == HTTPS_NO_ERROR) {
                        switch (WEXITSTATUS(sp->exit_status)) {
                        case 0:
                            result->https_error = HTTPS_NO_ERROR;
                            break;
                        case 4:
                            // "Network failure" may include DNS lookup failures, which aren't
                            // a reliable indication of blocking.
                            // request->https_error = HTTPS_SOCKET_IO_ERROR;
                            result->https_error = HTTPS_GENERIC_ERROR;
                            break;
                        case 5:
                            result->https_error = HTTPS_TLS_ERROR;
                            break;
                        case 8:
                            result->https_error = HTTPS_HTTP_ERROR;
                            // alas, wget doesn't make it easy for us to get the http status code
                            break;
                        default:
                            result->https_error = HTTPS_GENERIC_ERROR;
                            break;
                        }
                    }
                    debug("%s: %s https_error = %d (%s)(%s)\n", __func__, sp->name, result->https_error,
                          https_strerror(result),
                          likely_blocked(result) ? "likely blocked" : "not blocked");
                    if (sp->cb) {
                        uint64_t now = us_clock();
                        result->xfer_time_us = now - result->xfer_start_time_us;
                        // if there's an output file and room in the buffer, read
                        // the contents of the output file into the buffer
                        if ((sp->flags & HASOUTPUTFILE) && sp->outputfilename && request->bufsize > 0) {
                            int fd = open(sp->outputfilename, O_RDONLY);
                            if (fd >= 0) {
                                off_t filesize = fdsize(fd);
                                int nread;
                                off_t response_length;
                                response_length = MIN(filesize, (off_t) request->bufsize);
                                result->response_body = response_length > 0 ? malloc(response_length) : NULL;

                                result->response_length = 0;
                                if (result->response_body) {
                                    while (result->response_length < request->bufsize) {
                                        nread = read(fd, 
                                                     result->response_body + result->response_length,
                                                     request->bufsize - result->response_length);
                                        if (nread > 0) {
                                            result->response_length += nread;
                                        } else {
                                            break;
                                        }
                                    }
                                    if (filesize > (off_t) request->bufsize) {
                                        result->result_flags |= HTTPS_RESULT_TRUNCATED;
                                    }
                                }
                                close (fd);
                            }
                            unlink(sp->outputfilename);
                            free(sp->outputfilename);
                            sp->outputfilename = NULL;
                        }
                        network_async(g_n, ^{
                            // check cancelled flag again - it may have changed
                            // it is also possible that subproc slot has been reallocated
                            if (sp->request_id == request_id) {
                                if ((sp->flags & CANCELLED) == 0) {
                                    // XXX (sp->cb)(WEXITSTATUS(sp->exit_status) == 0 ? true : false, result);
                                    (sp->cb)(WEXITSTATUS(sp->exit_status) == 0 ? true : false);
                                }
                                free_subproc(sp);
                            }
                        });
                    }
                }
            }
            else if (WIFSIGNALED(sp->exit_status)) {
                if (sp->flags & CANCELLED) {
                    debug("%s: process pid:%d request_id:%" PRId64 " name:%s) killed with signal %d (%s) was already cancelled\n",
                          __func__, sp->pid, sp->request_id, sp->name, WTERMSIG(sp->exit_status), strsignal(WTERMSIG(sp->exit_status)));
                    free_subproc(sp);
                } else {
                    debug("%s: process pid:%d request_id:%" PRId64 " name:%s) killed with signal %d (%s)\n",
                          __func__, sp->pid, sp->request_id, sp->name, WTERMSIG(sp->exit_status),
                          strsignal(WTERMSIG(sp->exit_status)));
                    debug("%s sp->flags:(%s)\n", __func__, flags(sp->flags));
                    if (WTERMSIG(sp->exit_status) == SIGXFSZ) {
                        result->result_flags |= HTTPS_RESULT_TRUNCATED;
                    }
                    else if (result->https_error == HTTPS_NO_ERROR) {
                        result->https_error = HTTPS_GENERIC_ERROR;
                    }
                    debug("%s: %s https_error = %d (%s)(%s)\n", __func__, sp->name, result->https_error,
                          https_strerror(result),
                          likely_blocked(result) ? "likely blocked" : "not blocked");
                    if (sp->cb) {
                        // if there's an output file and room in the
                        // buffer, read the contents of the output
                        // file into the buffer (if we have received a
                        // SIGXFSZ signal, we still want what we can
                        // get from the buffer)
                        if ((sp->flags & HASOUTPUTFILE) && sp->outputfilename && request->bufsize > 0) {
                            int fd = open(sp->outputfilename, O_RDONLY);
                            if (fd) {
                                off_t filesize = fdsize(fd);
                                int nread;
                                off_t response_length;
                                response_length = MIN(filesize, (off_t) request->bufsize);
                                result->response_body = response_length > 0 ? malloc(response_length) : NULL;

                                result->response_length = 0;
                                if (result->response_body) {
                                    while (result->response_length < request->bufsize) {
                                        nread = read(fd, 
                                                     result->response_body + result->response_length,
                                                     request->bufsize - result->response_length);
                                        if (nread > 0) {
                                            result->response_length += nread;
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                close (fd);
                            }
                            unlink(sp->outputfilename);
                            free(sp->outputfilename);
                            sp->outputfilename = NULL;
                        }
                        network_async(g_n, ^{
                            // check CANCELLED flag again since it
                            // may have changed by the time the
                            // timer_callback is called
                            if (sp->request_id == request_id) {
                                if ((sp->flags & CANCELLED) == 0) {
                                    //XXX (sp->cb)(false, result);
                                    (sp->cb)(false);
                                }
                                free_subproc(sp);
                            }
                        });
                    }
                }
            } else {
                // got a SIGCHLD for this process but its exit status shows neither
                // that it exited nor died of a signal.   maybe this never happens?
                debug("not sure what happened to pid %d with exit status 0x%x\n",
                      sp->pid, sp->exit_status);
                free_subproc(sp);
            }
        }
    }
}

// cancel a request that might be in progress
//
// A cancelled request doesn't ever call its completion callback.

void
cancel_https_request(int64_t request_id)
{
    int i;
    extern network *g_n;

    debug("%s (%" PRId64 ")\n", __func__, request_id);
    if (request_id <= 0) {
        return;
    }
    //
    // XXX instead of iterating through loop calculate i from request_id
    //
    for (i = 0; i < NSUBPROC; ++i) {            // XXX change < NSUBPROC to <= max_subproc
        if (subprocs[i].request_id == request_id) {
            if (subprocs[i].flags & INUSE) {
                // debug("XXX request_id:%" PRId64 " request_id%%NSUBPROC=%" PRId64 " i=%d\n", request_id,
                //       request_id % NSUBPROC, i);
                // debug("XXX %s: found subproc[%d] with request_id:%" PRId64 "\n", __func__, i, request_id);
                subprocs[i].flags |= CANCELLED;             // inhibit completion callback
                // do the kill() in a timer callback so that the resulting SIGCHLD
                // doesn't trigger an immediate event and prevent connect_cleanup()
                // from completing.  (wait 100ms - just a guess)
                int pid = subprocs[i].pid;
                if (pid) {
                    timer_start(g_n, 100, ^{
                        kill(pid, SIGINT);
                        debug("%s: process %d killed\n", __func__, pid);
                    });
                }
                // don't call free_subproc here, wait until the SIGCHLD handler is called
                return;
            } else {
                // subproc no longer in use
                return;
            }
        }
    }
    debug("%s request_id:%" PRId64 " not found in subproc list\n", __func__, request_id);
}

static char *
make_temp_filename()
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "/var/tmp/nn%08x", randombytes_uniform(0xffffffff));
    return strdup(buf);
}

static struct https_request default_request = { 0 };

int64_t
https_wget(network *n, int http_port, const char *url, https_complete_callback cb, struct https_request *request)
{
    static int inited = 0;
    char buf[128];
    char *child_argv[20];
    int child_stdout = 0;
    int child_socket = 0;
    char *envp_mods[2];
    pid_t pid;
    struct subproc *sp;
    int s[2] = { 0, 0 };
    char timeout_str[30];
    struct event *child_exit_event;
    struct event *child_output_event = NULL;
    size_t maxoutputfilesize = 0;
    bool use_head = false;
    bool range_one_byte = false;
    bool follow_redirects = true;
    bool no_retries = false;

    if (!inited) {
        // libevent has the built-in ability to treat signals as
        // events and assign callbacks to them.  So treat SIGCHLD as
        // an event and get a callback whenever a child process exits.
        child_exit_event = event_new(n->evbase, SIGCHLD, EV_SIGNAL|EV_PERSIST, child_exit_event_cb, 0);
        event_add(child_exit_event, NULL);
        inited = 1;
    }
    if (request->bufsize > MAX_BUFSIZE && cb) {
        // call the completion handler with an error, so we always report errors consistently
        timer_start(n, 100, ^{
#if 0
            // XXX
            https_result result;
            memset(&result, 0, sizeof(result));
            result.https_error = HTTPS_RESOURCE_EXHAUSTED;
            cb(false, &result);
#else
            cb(false);
#endif
        });
    }
    sp = alloc_subproc(request);
    if (sp == NULL && cb) {
        // call the completion handler with an error, so we always report errors consistently
        timer_start(n, 100, ^{
#if 0
            // XXX
            https_result result;
            memset(&result, 0, sizeof(result));
            result.https_error = HTTPS_RESOURCE_EXHAUSTED;
            cb(false, &result);
#else
            cb(false);
#endif
        });
        // 0 is not a valid request_id and will be ignored in cancel requests
        debug("%s (%s:%d) could not allocate subprocess\n", __func__, __FILE__, __LINE__);
        return 0;
    }
    if (request) {
        memcpy(&(sp->request), request, sizeof(struct https_request));
    } else {
        // default if request == NULL: bufsize=0, HTTPS_DIRECT=0, default timeout
        memcpy(&(sp->request), &default_request, sizeof(struct https_request));
        sp->request.timeout_sec = 7;
    }


    if (sp->request.flags & HTTPS_USE_HEAD) {
        use_head = true;
    }
    if (sp->request.flags & HTTPS_ONE_BYTE) {
        range_one_byte = true;
    }
    if (sp->request.flags & HTTPS_NO_REDIRECT) {
        follow_redirects = false;
    }
    if (sp->request.flags & HTTPS_NO_RETRIES) {
        no_retries = true;
    }

    // alloc_subproc initialized result fields to zeros
    // get start times
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    sp->result.req_time = now.tv_sec;
    sp->result.xfer_start_time_us = us_clock();

    if (request->bufsize > 0) {
        // response body was requested, so have wget write the
        // response to a temporary file.  The exit handler will copy
        // that file to a malloc'ed buffer pointed to by the result
        // structure.
        int i = 0;

        maxoutputfilesize = request->bufsize;
        sp->outputfilename = make_temp_filename();
        sp->flags |= HASOUTPUTFILE;
        child_argv[i++] = "wget";
        child_argv[i++] = (char *) url;
        child_argv[i++] = "-o";         // get rid of wget-log* files
        child_argv[i++] = "/dev/null";
        child_argv[i++] = "-O";
        child_argv[i++] = sp->outputfilename;
        if (use_head) {
            child_argv[i++] = "--method=HEAD";
        }
        if (range_one_byte) {
            child_argv[i++] = "--header=Range: bytes=0,1";
        }
        if (no_retries) {
            child_argv[i++] = "--tries=1";
        }
        if (!follow_redirects) {
            child_argv[i++] = "--max-redirect=0";
        }
        if (request->timeout_sec != 0) {
            snprintf(timeout_str, sizeof(timeout_str), "%d", request->timeout_sec);
            child_argv[i++] = "-T";
            child_argv[i++] = timeout_str;
        }
        if (o_debug == 0) {
            child_argv[i++] = "-q";
        }
        child_argv[i++] = NULL;
        if (o_debug > 0) {
            fprintf (stderr, "https_wget: ");
            for (int ii = 0; child_argv[ii]; ++ii)
                fprintf(stderr, "%s ", child_argv[ii]);
            fprintf(stderr, "\n");
        }
    } else {
        // no response body was requested, have wget write to /dev/null
        int i = 0;
        child_argv[i++] = "wget";
        child_argv[i++] = (char *) url;
        child_argv[i++] = "-o";         // get rid of wget-log* files
        child_argv[i++] = "/dev/null";
        child_argv[i++] = "-O";
        child_argv[i++] = "/dev/null";
        if (use_head) {
            child_argv[i++] = "--method=HEAD";
        }
        if (range_one_byte) {
            child_argv[i++] = "--header=Range: bytes=0,1";
        }
        if (no_retries) {
            child_argv[i++] = "--tries=1";
        }
        if (!follow_redirects) {
            child_argv[i++] = "--max-redirect=0";
        }
        if (request && request->timeout_sec != 0) {
            snprintf(timeout_str, sizeof(timeout_str), "%d", request->timeout_sec);
            child_argv[i++] = "-T";
            child_argv[i++] = timeout_str;
        }
        if (o_debug == 0) {
            child_argv[i++] = "-q";
        }
        child_argv[i++] = NULL;
        if (o_debug > 0) {
            fprintf(stderr, "https_wget: ");
            for (int ii = 0; child_argv[ii]; ++ii)
                fprintf(stderr, "%s ", child_argv[ii]);
            fprintf(stderr, "\n");
        }
    }
    if (sp->request.flags & HTTPS_DIRECT) {
        envp_mods[0] = NULL;
        envp_mods[1] = NULL;
    } else {
        snprintf(buf, sizeof(buf), "https_proxy=http://127.0.0.1:%d", http_port);
        envp_mods[0] = buf;
        envp_mods[1] = NULL;
    }

    sp->cb = Block_copy(cb);
    sp->name = strdup(url);
    sp->child_stdout = child_stdout;
    pid = spawn(sp, PATH_WGET, child_argv, child_stdout, envp_mods, maxoutputfilesize);
    debug("started wget on pid:%d sp:%p\n", pid, sp);
    debug("%s (%s) returning %" PRId64 "\n", __func__, url, sp->request_id);
    return sp->request_id;
}

#include "dns_prefetch.h"

struct user_data {
    int index;
    uint64_t id;
    char *host;
};

void evdns_callback(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
    struct user_data *data = (struct user_data *) ptr;
    if (errcode) {
        debug("evdns_callback(%s) -> %s\n", data->host,
              evutil_gai_strerror(errcode));
    } else {
        struct nn_addrinfo *result;
        extern char *make_ip_addr_list(struct nn_addrinfo *r);

        result = copy_nn_addrinfo_from_evutil_addrinfo(addr);
        // no need for timer_start() here, as this always runs in libevent thread
        dns_prefetch_store_result(data->index, data->id, result, data->host, true);
        debug("%s: host:%s addrs:%s\n", __func__, data->host, make_ip_addr_list(result));
        if (data) {
            if (data->host) {
                free(data->host);
                data->host = NULL;
            }
            free(data);
        }
    }
}

void
platform_dns_prefetch(int result_index, unsigned int result_id, const char *host)
{
    struct evdns_getaddrinfo_request *req;
    struct evutil_addrinfo hints;
    struct user_data *user_data;
    extern network *g_n;

    memset(&hints, 0, sizeof (struct evutil_addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    user_data = alloc(struct user_data);
    user_data->host = strdup(host);
    user_data->id = result_id;
    user_data->index = result_index;
    req = evdns_getaddrinfo(g_n->evdns, host, NULL, &hints, evdns_callback, user_data);
    if (req == NULL) {
        debug("evdns_getaddrinfo(%s) returned immediately\n", host);
    }
}
