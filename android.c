#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include <jni.h>
#include <android/log.h>

#include "bugsnag/bugsnag_ndk.h"

#include "network.h"
#include "thread.h"
#include "constants.h"
#include "log.h"
#include "newnode.h"
#include "d2d.h"
#include "lsd.h"
#include "inttypes.h"
#include "dns_prefetch.h"

static int pfd[2];
static JavaVM *g_jvm;
static jobject bugsnagClient;
static jobject newNode;
static network *g_n;

// keep an array of requests that are associated with small integers
// so that we can maintain per-download state separately from NN state
// while allowing NN to cancel requests.

#define NLINK 100

static struct link {
    jlong request_id;                // structure is unused if request_id == 0
    volatile bool cancelled;    // nonzero if cancelled by NewNode
    https_request request;
    https_complete_callback completion_cb;
    https_result result;
} links[NLINK];

static jlong request_serial = 1; // request_ids are always > 0

static int alloc_link(https_request *hr)
{
    for (int i = 0; i < NLINK; ++i) {
        if (links[i].request_id == 0) {
            links[i].request_id = (request_serial++ * NLINK) + i;
            links[i].cancelled = false;
            if (hr) {
                links[i].request = *hr;
            } else {
                // implement defaults if request==NULL
                // (bufsize=0, flags=0, timeout_sec=7)
                memset(&(links[i].request), 0, sizeof(https_request));
                links[i].request.timeout_sec = 7;
            }
            links[i].completion_cb = NULL;
            memset(&(links[i].result), 0, sizeof(https_result));
            if (hr) {
                if (hr->flags & HTTPS_USE_HEAD) {
                    links[i].result.result_flags |= HTTPS_REQUEST_USE_HEAD;
                }
                if (hr->flags & HTTPS_ONE_BYTE) {
                    links[i].result.result_flags |= HTTPS_REQUEST_ONE_BYTE;
                }
            }
            links[i].result.request_id = links[i].request_id;
            return i;
        }
    }
    return -1;
}

// NOTE: this should always be called from the libevent thread
// otherwise, alloc_link() might be called concurrently with free_link

static void free_link(jlong request_id)
{
    if (request_id <= 0) {
        return;
    }
    int i = request_id % NLINK;
    if (links[i].request_id == request_id) {
        if (links[i].result.response_body != NULL) {
            free(links[i].result.response_body);
            links[i].result.response_body = NULL;
        }
        links[i].request_id = 0;
        links[i].cancelled = false;
        memset(&(links[i].request), 0, sizeof(https_request));
        links[i].completion_cb = NULL;
        memset(&(links[i].result), 0, sizeof(https_result));
        return;
    }
    // debug("XXX %s links[%d].request_id %" PRId64 " != request_id %" PRId64 "\n",
    //       __func__, i, links[i].request_id, request_id);
}

// find the link with the specified request_id
// return the index of the link in the links array

static int find_link(jlong request_id)
{
    if (request_id <= 0) {
        return -1;
    }
    int i = request_id % NLINK;
    if (links[i].request_id == request_id) {
        return i;
    }
    // debug("XXX %s request_id %" PRId64 " not found at index %d\n", __func__, request_id, i);
    return -1;
}

// this function exists to allow NewNode to cancel an https request
// that is in progress
//
// XXX for now all this does is set a cancelled flag; it doesn't
//     actually try to stop the thread handling the request

void cancel_https_request(network *n, int64_t request_id)
{
    debug("%s (request_id:%" PRId64 ")\n", __func__, request_id);
    int link_index = find_link((jlong) request_id);
    if (link_index < 0) {
        debug("%s could not find link %" PRId64 "\n", __func__, request_id);
        return;
    }
    links[link_index].cancelled = true;
}

void* stdio_thread(void *useradata)
{
    ssize_t readSize;
    char buf[1024];

    while ((readSize = read(pfd[0], buf, sizeof buf - 1)) > 0) {
        if (buf[readSize - 1] == '\n') {
            --readSize;
        }
        buf[readSize] = 0;
        __android_log_write(ANDROID_LOG_VERBOSE, "newnode", buf);
    }
    return NULL;
}

void start_stdio_thread()
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    pipe(pfd);
    dup2(pfd[1], 1);
    dup2(pfd[1], 2);
    pthread_t t;
    if (pthread_create(&t, NULL, stdio_thread, NULL) == -1) {
        return;
    }
    pthread_detach(t);
}

#define BUGSNAG_API_KEY "141ea25aa72c276c49d3a154b82f2b1f"

#define STR(A) #A

#define JSTR(s) (*env)->NewStringUTF(env, s)

#define IMPORT(pkg, class) jclass c ## class = (*env)->FindClass(env, STR(pkg) "/" STR(class));
#define IMPORT_INNER(pkg, class) jclass c ## class = (*env)->FindClass(env, STR(pkg) "$" STR(class));

#define CALL_VOID(class, obj, meth, sig, ...) \
 jmethodID m ## meth = (*env)->GetMethodID(env, class, #meth, "(" STR(sig) ")V"); \
 if (m ## meth) (*env)->CallVoidMethod(env, obj, m ## meth, __VA_ARGS__);

#define CATCH(code) if ((*env)->ExceptionOccurred(env)) { \
  (*env)->ExceptionDescribe(env); \
  (*env)->ExceptionClear(env); \
  code; \
}

#define push_frame() (*env)->PushLocalFrame(env, 16)
#define pop_frame() (*env)->PopLocalFrame(env, NULL);


void jvm_frame(JNIEnv* env, void (^c)())
{
    push_frame();
    c();
    pop_frame();
}

enum notify_type {
    ALL = 1,
    USER = 2,
    APP = 3,
    DEVICE = 4,
    CONTEXT = 5,
    RELEASE_STAGES = 6,
    FILTERS = 7,
    BREADCRUMB = 8,
    META = 9
};

JNIEXPORT jint Java_com_clostra_newnode_internal_NewNode_isCancelled(JNIEnv *env, jobject thiz, jlong request_id)
{
    jint result;
    int link_index = find_link(request_id);
    if (link_index < 0) {
        return 1;
    }
    result = links[link_index].cancelled;
    // debug("isCancelled(request_id:%ld) => %d\n", request_id, result);
    return result;
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_updateBugsnagDetails(JNIEnv* env, jobject thiz, int notifyType)
{
    static bool bugsnag_setup = false;
    if (!bugsnag_setup) {
        bugsnag_setup = true;
        setupBugsnag(env);
    }
    switch ((enum notify_type)notifyType) {
    case USER: Java_com_bugsnag_android_ndk_BugsnagObserver_populateUserDetails(env, NULL); break;
    case APP: Java_com_bugsnag_android_ndk_BugsnagObserver_populateAppDetails(env, NULL); break;
    case DEVICE: Java_com_bugsnag_android_ndk_BugsnagObserver_populateDeviceDetails(env, NULL); break;
    case CONTEXT: Java_com_bugsnag_android_ndk_BugsnagObserver_populateContextDetails(env, NULL); break;
    case RELEASE_STAGES: Java_com_bugsnag_android_ndk_BugsnagObserver_populateReleaseStagesDetails(env, NULL); break;
    case FILTERS: Java_com_bugsnag_android_ndk_BugsnagObserver_populateFilterDetails(env, NULL); break;
    case BREADCRUMB: Java_com_bugsnag_android_ndk_BugsnagObserver_populateBreadcumbDetails(env, NULL); break;
    case META: Java_com_bugsnag_android_ndk_BugsnagObserver_populateMetaDataDetails(env, NULL); break;
    case ALL:
    default:
        Java_com_bugsnag_android_ndk_BugsnagObserver_populateErrorDetails(env, NULL); break;
    }
}

void bugsnag_leave_breadcrumb_log(const char *buf)
{
    bsg_breadcrumb *crumb = bugsnag_breadcrumb_init("newnode", BSG_CRUMB_LOG);
    bugsnag_breadcrumb_add_metadata(crumb, "stdout", (char*)buf);
    bugsnag_add_breadcrumb(crumb);
}

JNIEnv* get_env()
{
    JNIEnv *env;
    int stat = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    assert(stat == JNI_OK);
    return env;
}

// Request that the platform's DNS asychronously library query IPv4
// and IPv6 addresses (as appropriate) for 'host'.  The results are
// stored in dns_prefetch_cache_entries[cache_index] (so that NN can
// connect directly to an address) and hopefully also in the
// platform's DNS cache so that any "try first" attempts will be
// faster.
//
// This routine doesn't return a result.  NN will use the result of
// the query if it arrives in time, otherwise NN will use evdns
// (sigh).

void platform_dns_prefetch(network *n, int result_index, unsigned int result_id, const char *host)
{
    debug("%s result_index:%d result_id:%u host:%s\n", __func__, result_index, result_id, host);
    if (!newNode) {
        return;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
    JNIEnv *env = get_env();
#pragma clang diagnostic pop
    if (env == NULL) {
        return;
    }
    jvm_frame(env, ^() {
        jclass cNewNode = (*env)->GetObjectClass(env, newNode);
        CATCH(
            debug("%s exception line %d\n", __func__, __LINE__);
            return;
        );
        CALL_VOID(cNewNode, newNode,
                  dnsPrefetch,      // shorthand form of method name
                  Ljava/lang/String;II,  // parameter types:
                                         // (1) String hostname (Ljava/lang/String;)
                                         // (2) int result_index (I)
                                         // (3) int result_id (I)
                  JSTR(host),       // url (encoded as Java String)
                  (jint) result_index,
                  (jint) result_id);
        CATCH(
            debug("%s exception line %d\n", __func__, __LINE__);
            return;
        );
    });
}

// updates global array dns_prefetch_results[result_index].result with the results of DNS lookup of 'host'.

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_storeDnsPrefetchResult(JNIEnv *env, jobject thiz, jint result_index, jint result_id, jstring host, jobjectArray addresses)
{
    nn_addrinfo *result = NULL;
    nn_addrinfo *lastitem = NULL;

    if (result_id < 0) {
        return;
    }

    if (dns_prefetch_results[result_index].id != (unsigned int)result_id ||
        dns_prefetch_results[result_index].allocated != true) {
        return;
    }

    const char *hoststr = (*env)->GetStringUTFChars(env, host, NULL);
    int n_addresses = (*env)->GetArrayLength(env, addresses);

    debug("storeDnsPrefetchResult result_index:%d result_id:%d host:%s n_addresses:%d\n",
          result_index, result_id, hoststr, n_addresses);

    // convert each text address to binary form using getaddrinfo()
    // then add the result of that conversion to the end of the linked list
    for (int i = 0; i < n_addresses; ++i) {
        jstring string = (jstring) ((*env)->GetObjectArrayElement(env, addresses, i));
        const char *utf8string = (*env)->GetStringUTFChars(env, string, 0);

        debug("storeDnsPrefetchResult host:%s address[%d] = %s\n", hoststr, i, utf8string);
        addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_flags = AI_NUMERICHOST
        };
        addrinfo *temp = NULL;
        int err = getaddrinfo(utf8string, NULL, &hints, &temp);
        if (err == 0) {
            nn_addrinfo *n = alloc(nn_addrinfo);
            debug("storeDnsPrefetchResult i:%d result:%p lastitem:%p n:%p\n", i, result, lastitem, n);
            if (n && temp && temp->ai_addr) {
                n->ai_addrlen = temp->ai_addrlen;
                n->ai_addr = memdup(temp->ai_addr, temp->ai_addrlen);
                n->ai_next = NULL;
                // append to linked list
                if (!result) {
                    result = n;
                } else {
                    lastitem->ai_next = n;
                }
                lastitem = n;
            }
            if (temp) {
                freeaddrinfo(temp);
            }
        } else {
            debug("storeDnsPrefetchResult gai_strerror(%s) => %s\n", utf8string, gai_strerror(err));
        }
        (*env)->ReleaseStringUTFChars(env, string, utf8string);
    }
    // nn_addrinfo *p;
    // debug("storeDnsPrefetchResult:\n");
    // for (p = result; p; p = p->ai_next) {
    //     debug("    %s\n", sockaddr_str(p->ai_addr));
    // }

    // copy hoststr for use by callback
    // (the blocks callback may happen after ReleaseStringUTFChars is called)
    char *temp_hoststr = strdup(hoststr);
    network_async(g_n, ^{
        dns_prefetch_store_result(g_n, result_index, result_id, result, temp_hoststr, false);
        free(temp_hoststr);
    });
    (*env)->ReleaseStringUTFChars(env, host, hoststr);
}

// callback() passes lots of scalar result parameters from Java code
// that then get copied into an https_result structure (if the
// request wasn't cancelled), because it seemed easier than either
// having the Java code return a class instance, or having the Java
// code manipulate a C data structure on the C heap.


// XXX are all of these arguments still needed?
//     NO, but wait until later to rearrange them
//     needed: request_id, response_body, response_length, https_error, http_status_code, result_flags

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_callback(JNIEnv* env, jobject thiz, jlong callblock, jlong response_length, jint https_error, jint http_status_code, jint result_flags, jlong request_id, jbyteArray response_body)
{
    extern char *https_strerror();
    https_result dummy_res;
    dummy_res.https_error = https_error;
   
    debug("g_https_cb callback response_length:%ld https_error:%d(%s) http_status_code:%d result_flags:0x%x request_id:%lld\n", 
          (long) response_length, https_error, https_strerror(&dummy_res),
          http_status_code, result_flags, (long long) request_id);

    int link_index = find_link(request_id);
    if (link_index < 0) {
        return;
    }

    if (links[link_index].cancelled) {
        // if cancelled, free any data that is internal to this module,
        // and don't call the completion callback
        network_async(g_n, ^{
            free_link(request_id);
            debug("%s request_id:%lld was cancelled\n", __func__, (long long) request_id);
        });
        return;
    }

    // fill in the result fields in Java's thread,
    // (especially so we can copy out the response_body array contents safely)
    https_request *req = &(links[link_index].request);
    https_result *res =  &(links[link_index].result);
    // copy min(req->bufsize, response_length) bytes from result into res->buf
    jsize array_length = (*env)->GetArrayLength(env, response_body);
    if (response_length > 0 && http_status_code == 200) {
        long minimum = array_length;
        if (response_length < minimum) {
            minimum = response_length;
        }
        if ((long)(req->bufsize) < minimum) {
            minimum = req->bufsize;
        }
        res->response_body = malloc(minimum);
        (*env)->GetByteArrayRegion(env, response_body, 0, minimum, (jbyte *) res->response_body);
        // debug("response_body=%.*s\n", response_length > 80 ? 80 : (int) response_length, req->buf);
        res->response_length = response_length;
    }
    res->result_flags = result_flags;
    res->xfer_time_us = us_clock() - res->xfer_start_time_us;
    res->https_error = https_error;
    res->http_status = http_status_code;

    https_complete_callback cb = (https_complete_callback)callblock;
    if (links[link_index].cancelled == 0) {
        network_async(g_n, ^{
            if (links[link_index].request_id == request_id && links[link_index].cancelled == 0) {
                cb(http_status_code == 200, res);
                Block_release(cb);
                free_link(request_id);
            }
        });
    } else {
        Block_release(cb);
        network_async(g_n, ^{
            free_link(request_id);
        });
    }
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_newnodeInit(JNIEnv* env, jobject thiz, jobject newNodeObj)
{
    newNode = (*env)->NewGlobalRef(env, newNodeObj);

    network_set_log_level(1);

    char app_id[64] = {0};
    FILE *cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fread(app_id, sizeof(app_id), 1, cmdline);
        __android_log_print(ANDROID_LOG_DEBUG, "newnode", "application id %s\n", app_id);
        fclose(cmdline);
    }
    // XXX: TODO: use real app name
    const char *app_name = app_id;
    port_t newnode_port = 0;
    g_n = newnode_init(app_name, app_id, &newnode_port, ^int64_t (const char* url, https_complete_callback cb, https_request *request) {
        network *n = g_n;
        int link_index = alloc_link(request);
        if (link_index < 0) {
            network_async(n, ^{
                https_result fake_result = {.https_error = HTTPS_RESOURCE_EXHAUSTED};
                cb(false, &fake_result);
            });
            return 0;
        }
        jlong request_id = links[link_index].request_id;
        https_result *result = &(links[link_index].result);
        timespec now;
        // TODO: use us_clock()
        clock_gettime(CLOCK_REALTIME, &now);
        result->req_time = now.tv_sec;
        debug("g_https_cb(%s) request_id:%lld link_index:%d\n", url, (long long)request_id, link_index);
        result->xfer_start_time_us = us_clock();
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
        JNIEnv *env = get_env();
#pragma clang diagnostic pop
        jvm_frame(env, ^{
            if (!newNode) {
                network_async(n, ^{
                    if (links[link_index].request_id == request_id) {
                        result->https_error = HTTPS_SYSCALL_ERROR;
                        cb(false, result);
                        free_link(request_id);
                    }
                });
                return;
            }
            jclass cNewNode = (*env)->GetObjectClass(env, newNode);
            CATCH(
                  network_async(n, ^{
                      if (links[link_index].request_id == request_id) {
                          result->https_error = HTTPS_SYSCALL_ERROR;
                          cb(false, result);
                          free_link(request_id);
                      }
                  });
                return;
            );
            https_complete_callback cbc = Block_copy(cb);
 
            // debug("(jni call) http(url:%s, cbc:%p, flags:0x%08x, timeout:%d, bufsize:%lu, request_id:%d)\n",
            //       url, cbc, request->flags, request->timeout_sec, (unsigned long) request->bufsize, request_id);
            // debug("           flags=%s\n", expand_flags(request->flags));
            CALL_VOID(cNewNode, newNode, 
                      http,                     // shorthand form of method name
                      Ljava/lang/String;JIIIJI, // parameter types:
                                                // (1) String url (Ljava/lang/String;)
                                                // (2) long cbc (J)
                                                // (3) int request_flags (I)
                                                // (4) int timeout_msec (I)
                                                // (5) int bufsize (I)
                                                // (6) long request_id (J)
                                                // (7) int newnode_port (I)
                      JSTR(url),                // url (encoded as Java String)
                      (jlong)cbc,               // callback pointer (encoded as long)
                      (jint)(request->flags),   // request flags
                      (jint)(request->timeout_sec * 1000), // timeout_msec
                      (jint)(request->bufsize), // bufsize
                      (jlong) request_id,        // request_id
                      (jint) newnode_port);        // http_port
            CATCH(
                  network_async(n, ^{
                      if (links[link_index].request_id == request_id) {
                          result->https_error = HTTPS_SYSCALL_ERROR;
                          cb(false, result);
                          free_link(request_id);
                          Block_release(cbc);
                      }
                  });
            );
        });
        return links[link_index].request_id;
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    const char* cCacheDir = (*env)->GetStringUTFChars(env, cacheDir, NULL);
    chdir(cCacheDir);
    (*env)->ReleaseStringUTFChars(env, cacheDir, cCacheDir);
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_registerProxy(JNIEnv* env, jobject thiz)
{
    port_t newnode_port = newnode_get_port(g_n);
    if (!newnode_port) {
        return;
    }

    IMPORT(java/lang, System);
    CATCH(return);
    jmethodID mSetProp = (*env)->GetStaticMethodID(env, cSystem, "setProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    CATCH(return);

    char port[6];
    snprintf(port, sizeof(port), "%u", newnode_port);
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("socksProxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("socksProxyPort"), JSTR(port));

    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("proxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("proxyPort"), JSTR(port));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("http.proxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("http.proxyPort"), JSTR(port));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("https.proxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("https.proxyPort"), JSTR(port));

    char proxy[128];
    snprintf(proxy, sizeof(proxy), "http://127.0.0.1:%s", port);
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("http_proxy"), JSTR(proxy));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("https_proxy"), JSTR(proxy));
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_unregisterProxy(JNIEnv* env, jobject thiz)
{
    IMPORT(java/lang, System);
    CATCH(return);
    jmethodID mClearProp = (*env)->GetStaticMethodID(env, cSystem, "clearProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    CATCH(return);
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("socksProxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("socksProxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("proxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("proxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("http.proxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("http.proxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("https.proxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("https.proxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("http_proxy"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("https_proxy"));
}

bool vpn_protect(int socket)
{
    JNIEnv *env = get_env();
    push_frame();
    bool r = ^bool() {
        if (!newNode) {
            return false;
        }
        IMPORT(com/clostra/newnode/vpn, VpnService);
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
            return true;
        }
        jmethodID mVpnProtect = (*env)->GetStaticMethodID(env, cVpnService, "vpnProtect", "(I)Z");
        CATCH(return false);
        jboolean success = (*env)->CallStaticBooleanMethod(env, cVpnService, mVpnProtect, socket);
        CATCH(return false);
        return (bool)success;
    }();
    pop_frame();
    return r;
}

int __real_bind(int socket, const sockaddr *address, socklen_t length);
int __wrap_bind(int socket, const sockaddr *address, socklen_t length)
{
    //debug("bind %d %s\n", socket, sockaddr_str(address));
    if (!sockaddr_is_localhost(address, length) && !vpn_protect(socket)) {
        debug("bind failed to protect\n");
        errno = EADDRNOTAVAIL;
        return -1;
    }
    return __real_bind(socket, address, length);
}

int __real_connect(int socket, const sockaddr *address, socklen_t length);
int __wrap_connect(int socket, const sockaddr *address, socklen_t length)
{
    //debug("connect %d %s\n", socket, sockaddr_str(address));
    sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(socket, (sockaddr*)&ss, &slen) == -1 || slen == 0 || sockaddr_get_port((const sockaddr*)&ss) == 0) {
        if (!vpn_protect(socket)) {
            debug("connect failed to protect\n");
            errno = EADDRNOTAVAIL;
            return -1;
        }
    }
    return __real_connect(socket, address, length);
}

ssize_t __real_sendto(int socket, const void *buffer, size_t length, int flags, const sockaddr *dest_addr, socklen_t dest_len);
ssize_t __wrap_sendto(int socket, const void *buffer, size_t length, int flags, const sockaddr *dest_addr, socklen_t dest_len)
{
    //debug("sendto %d %s\n", socket, sockaddr_str(dest_addr));
    sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(socket, (sockaddr*)&ss, &slen) == -1 || slen == 0 || sockaddr_get_port((const sockaddr*)&ss) == 0) {
        if (!vpn_protect(socket)) {
            debug("sendto failed to protect\n");
            errno = EADDRNOTAVAIL;
            return -1;
        }
    }
    return __real_sendto(socket, buffer, length, flags, dest_addr, dest_len);
}

sockaddr_in6 jbyteArray_to_addr(JNIEnv* env, jbyteArray je)
{
    jbyte *buf = (*env)->GetByteArrayElements(env, je, NULL);
    jsize len = (*env)->GetArrayLength(env, je);
    endpoint e = {.port = 0};
    memcpy(&e, buf, MIN((size_t)len, sizeof(e)));
    (*env)->ReleaseByteArrayElements(env, je, buf, JNI_ABORT);
    return endpoint_to_addr(&e);
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_addEndpoint(JNIEnv* env, jobject thiz, jbyteArray endpoint)
{
    const sockaddr_in6 sin6 = jbyteArray_to_addr(env, endpoint);
    network_async(g_n, ^{
        add_sockaddr(g_n, (const sockaddr *)&sin6, sizeof(sin6));
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_removeEndpoint(JNIEnv* env, jobject thiz, jbyteArray endpoint)
{
    const sockaddr_in6 sin6 = jbyteArray_to_addr(env, endpoint);
    network_async(g_n, ^{
        // XXX: TODO: remove endpoint
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_packetReceived(JNIEnv* env, jobject thiz, jbyteArray array, jbyteArray endpoint)
{
    jobject arrayref = (*env)->NewGlobalRef(env, array);
    const sockaddr_in6 sin6 = jbyteArray_to_addr(env, endpoint);
    network_async(g_n, ^{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
        JNIEnv *env = get_env();
#pragma clang diagnostic pop
        jbyte *buf = (*env)->GetByteArrayElements(env, arrayref, NULL);
        jsize len = (*env)->GetArrayLength(env, arrayref);
        udp_received(g_n, (const uint8_t*)buf, len, (const sockaddr *)&sin6, sizeof(sin6));
        (*env)->ReleaseByteArrayElements(env, arrayref, buf, JNI_ABORT);
        (*env)->DeleteGlobalRef(env, arrayref);

        // XXX: this should be called when the read buffer is drained
        utp_issue_deferred_acks(g_n->utp);
    });
}

ssize_t d2d_sendto(const uint8_t* buf, size_t len, const sockaddr_in6 *sin6)
{
    JNIEnv *env = get_env();
    push_frame();
    ssize_t r = ^ssize_t() {
        if (!IN6_IS_ADDR_UNIQUE_LOCAL(&sin6->sin6_addr)) {
            return -1;
        }
        if (!newNode) {
            return -1;
        }
        const endpoint e = addr_to_endpoint(sin6);
        jbyteArray jendpoint = (*env)->NewByteArray(env, sizeof(endpoint));
        CATCH(return -1);
        (*env)->SetByteArrayRegion(env, jendpoint, 0, sizeof(endpoint), (const jbyte *)&e);
        CATCH(return -1);
        jbyteArray array = (*env)->NewByteArray(env, len);
        CATCH(return -1);
        (*env)->SetByteArrayRegion(env, array, 0, len, (const jbyte *)buf);
        CATCH(return -1);
        jclass cNewNode = (*env)->GetObjectClass(env, newNode);
        CATCH(return -1);
        CALL_VOID(cNewNode, newNode, sendPacket, [B[B, array, jendpoint);
        CATCH(return -1);
        return len;
    }();
    pop_frame();
    return r;
}

void ui_display_stats(const char *type, uint64_t direct, uint64_t peers)
{
    JNIEnv *env = get_env();
    jvm_frame(env, ^{
        jclass cNewNode = (*env)->GetObjectClass(env, newNode);
        CATCH(return);
        CALL_VOID(cNewNode, newNode, displayStats, Ljava/lang/String;JJ, JSTR(type), direct, peers);
        CATCH(return);
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_setLogLevel(JNIEnv* env, jobject thiz, jint level)
{
    network_set_log_level(level);
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_newnodeRun(JNIEnv* env, jobject thiz)
{
    newnode_run(g_n);
}


// XXX: compat. can be removed when we have a NewNode.aar loader here in JNI
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_updateBugsnagDetails(JNIEnv* env, jobject thiz, int notifyType)
{
    Java_com_clostra_newnode_internal_NewNode_updateBugsnagDetails(env, thiz, notifyType);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_useEphemeralPort(JNIEnv* env, jobject thiz)
{
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    Java_com_clostra_newnode_internal_NewNode_setCacheDir(env, thiz, cacheDir);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_registerProxy(JNIEnv* env, jobject thiz)
{
    Java_com_clostra_newnode_internal_NewNode_registerProxy(env, thiz);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_unregisterProxy(JNIEnv* env, jobject thiz)
{
    Java_com_clostra_newnode_internal_NewNode_unregisterProxy(env, thiz);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_setLogLevel(JNIEnv* env, jobject thiz, jint level)
{
    Java_com_clostra_newnode_internal_NewNode_setLogLevel(env, thiz, level);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_dcdn_Dcdn_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    Java_com_clostra_newnode_internal_NewNode_setCacheDir(env, thiz, cacheDir);
}

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    g_jvm = vm;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    start_stdio_thread();
    return JNI_VERSION_1_6;
}
