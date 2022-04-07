#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "utp.h"

#include "event2/util.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/bufferevent_struct.h"
#include "event2/bufferevent_compat.h"
#include "event2/event.h"

#include "libevent/mm-internal.h"

#include "obfoo.h"
#include "bufferevent_utp.h"

#ifndef MIN
#define MIN(a, b) (((a)<(b))?(a):(b))
#endif

typedef struct sockaddr sockaddr;
typedef struct evbuffer evbuffer;
typedef struct evbuffer_cb_info evbuffer_cb_info;
typedef struct event_base event_base;
typedef struct bufferevent bufferevent;
typedef struct bufferevent_ops bufferevent_ops;
typedef struct bufferevent_private bufferevent_private;

/* prototypes */
static int be_utp_enable(bufferevent *, short);
static int be_utp_disable(bufferevent *, short);
static void be_utp_destruct(bufferevent *);
static int be_utp_flush(bufferevent *, short, enum bufferevent_flush_mode);
static int be_utp_ctrl(bufferevent *, enum bufferevent_ctrl_op, union bufferevent_ctrl_data *);


typedef struct {
    bufferevent_private bev;
    utp_context *utp_ctx;
    utp_socket *utp;
    obfoo *obfoo;
    evbuffer *obfoo_input;
    evbuffer *obfoo_output;
} bufferevent_utp;

const bufferevent_ops bufferevent_ops_utp = {
    "utp",
    evutil_offsetof(bufferevent_utp, bev.bev),
    be_utp_enable,
    be_utp_disable,
    NULL, /* unlink */
    be_utp_destruct,
    bufferevent_generic_adj_existing_timeouts_,
    be_utp_flush,
    be_utp_ctrl,
};

/* Given a bufferevent, return a pointer to the bufferevent_utp that
 * contains it, if any. */
bufferevent_utp* bufferevent_utp_upcast(const bufferevent *bev)
{
    if (!BEV_IS_UTP(bev)) {
        return NULL;
    }
    bufferevent_utp *bev_o = (void*)( ((char*)bev) -
             evutil_offsetof(bufferevent_utp, bev.bev));
    EVUTIL_ASSERT(BEV_IS_UTP(&bev_o->bev.bev));
    return bev_o;
}

void bufferevent_socket_set_conn_address_utp_(bufferevent *bev, utp_socket *utp)
{
    bufferevent_private *bev_p = BEV_UPCAST(bev);
    sockaddr *addr = (sockaddr *)&bev_p->conn_address;
    socklen_t len = sizeof(bev_p->conn_address);
    if (addr->sa_family != AF_UNSPEC) {
        utp_getpeername(utp, addr, &len);
    }
}

ssize_t evbuffer_utp_write(evbuffer *buffer, utp_socket *utp)
{
    ssize_t total = 0;
    while (evbuffer_get_length(buffer)) {
        // the libutp interface for write is Very Broken.
        ssize_t len = MIN(1500, evbuffer_get_length(buffer));
        unsigned char *buf = evbuffer_pullup(buffer, len);
        ssize_t r = utp_write(utp, buf, len);
        if (r < 0) {
            fprintf(stderr, "utp_write failed\n");
            return -1;
        }
        if (!r) {
            break;
        }
        total += r;
        evbuffer_drain(buffer, r);
    }
    return total;
}

static void bufferevent_utp_flush_to_obfoo(bufferevent_utp *bev_utp)
{
    bufferevent *bufev = &bev_utp->bev.bev;
    bufferevent_private *bufev_p = BEV_UPCAST(bufev);
    short what = BEV_EVENT_WRITING;

    bufferevent_incref_and_lock_(bufev);

    ev_ssize_t atmost = bufferevent_get_write_max_(bufev_p);

    if (bufev_p->write_suspended) {
        goto done;
    }

    ssize_t res = -1;
    if (evbuffer_get_length(bufev->output)) {
        evbuffer_unfreeze(bufev->output, 1);
        // XXX: observe "atmost" to support rate-limiting
        size_t len = evbuffer_get_length(bufev->output);
        res = obfoo_output_filter(bufev->output, bev_utp->obfoo_output, bev_utp->obfoo);
        if (res == 0) {
            res = len;
        }
        evbuffer_freeze(bufev->output, 1);
        if (res == -1) {
            what |= BEV_EVENT_ERROR;
            goto error;
        }

        bufferevent_decrement_write_buckets_(bufev_p, res);
    }

    if (evbuffer_get_length(bufev->output) == 0) {
        event_del(&bufev->ev_write);
    }

    /*
     * Invoke the user callback if our buffer is drained or below the
     * low watermark.
     */
    if (res) {
        bufferevent_trigger_nolock_(bufev, EV_WRITE, 0);
    }

    goto done;

 error:
    bufferevent_disable(bufev, EV_WRITE);
    bufferevent_run_eventcb_(bufev, what, 0);

 done:
    bufferevent_decref_and_unlock_(bufev);
}

static void bufferevent_utp_flush_to_utp(bufferevent_utp *bev_utp)
{
    bufferevent *bufev = &bev_utp->bev.bev;

    bufferevent_incref_and_lock_(bufev);

    evbuffer_unfreeze(bev_utp->obfoo_output, 1);
    ssize_t fres = evbuffer_utp_write(bev_utp->obfoo_output, bev_utp->utp);
    evbuffer_freeze(bev_utp->obfoo_output, 1);
    if (fres == -1) {
        bufferevent_disable(bufev, EV_WRITE);
        bufferevent_run_eventcb_(bufev, BEV_EVENT_WRITING | BEV_EVENT_ERROR, 0);
    }

    bufferevent_decref_and_unlock_(bufev);
}

uint64 utp_on_state_change(utp_callback_arguments *a)
{
    bufferevent *bufev = (bufferevent*)utp_get_userdata(a->socket);
    
    if (!bufev) {
        return 0;
    }
    
    bufferevent_private *bufev_p = BEV_UPCAST(bufev);
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bufev);

    bufferevent_incref_and_lock_(bufev);

    switch (a->state) {
    case UTP_STATE_CONNECT:
        bufev_p->connecting = 0;
        bufferevent_socket_set_conn_address_utp_(bufev, bev_utp->utp);
        bufferevent_utp_flush_to_utp(bev_utp);
        bufferevent_run_eventcb_(bufev, BEV_EVENT_CONNECTED, 0);
        if (!(bufev->enabled & EV_WRITE) ||
            bufev_p->write_suspended) {
            event_del(&bufev->ev_write);
            break;
        }
        BEV_RESET_GENERIC_WRITE_TIMEOUT(bufev);
    case UTP_STATE_WRITABLE:
        bufferevent_utp_flush_to_obfoo(bev_utp);
        break;
    case UTP_STATE_EOF:
        bufferevent_disable(bufev, EV_READ);
        bufferevent_run_eventcb_(bufev, BEV_EVENT_EOF, 0);
        break;
    case UTP_STATE_DESTROYING:
        bev_utp->utp = NULL;
        event_del(&bufev->ev_write);
        event_del(&bufev->ev_read);
        break;
    }

    bufferevent_decref_and_unlock_(bufev);

    return 0;
}

uint64 utp_on_error(utp_callback_arguments *a)
{
    bufferevent *bufev = (bufferevent*)utp_get_userdata(a->socket);
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bufev);

    bufferevent_incref_and_lock_(bufev);

    bev_utp->utp = NULL;
    event_del(&bufev->ev_write);
    event_del(&bufev->ev_read);
    bufferevent_run_eventcb_(bufev, BEV_EVENT_ERROR, 0);

    bufferevent_decref_and_unlock_(bufev);

    return 0;
}

uint64 utp_on_read(utp_callback_arguments *a)
{
    bufferevent *bufev = (bufferevent*)utp_get_userdata(a->socket);
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bufev);
    bufferevent_private *bufev_p = BEV_UPCAST(bufev);
    short what = BEV_EVENT_READING;

    bufferevent_incref_and_lock_(bufev);

    BEV_RESET_GENERIC_READ_TIMEOUT(bufev);

    evbuffer_unfreeze(bev_utp->obfoo_input, 0);
    int res = evbuffer_add(bev_utp->obfoo_input, a->buf, a->len);
    evbuffer_freeze(bev_utp->obfoo_input, 0);

    if (res == -1) {
        /* error case */
        what |= BEV_EVENT_ERROR;
        goto error;
    }

    of_state s = bev_utp->obfoo->state;

    evbuffer_unfreeze(bufev->input, 0);
    ssize_t fres = obfoo_input_filter(bev_utp->obfoo_input, bufev->input, bev_utp->obfoo_output, bev_utp->obfoo);
    evbuffer_freeze(bufev->input, 0);

    if (fres < 0) {
        /* error case */
        what |= BEV_EVENT_ERROR;
        goto error;
    }

    bufferevent_decrement_read_buckets_(bufev_p, fres);

    if (s < OF_STATE_DISCARD && bev_utp->obfoo->state >= OF_STATE_DISCARD) {
        // writing is now possible, flush
        bufferevent_utp_flush_to_obfoo(bev_utp);
    }

    /* Invoke the user callback - must always be called last */
    bufferevent_trigger_nolock_(bufev, EV_READ, 0);

    goto done;

 error:
    bufferevent_disable(bufev, EV_READ);
    bufferevent_run_eventcb_(bufev, what, 0);

 done:
    bufferevent_decref_and_unlock_(bufev);

    return 0;
}

static void bufferevent_utp_outbuf_cb(evbuffer *buf, const evbuffer_cb_info *cbinfo, void *arg)
{
    bufferevent *bufev = arg;
    bufferevent_private *bufev_p = BEV_UPCAST(bufev);
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bufev);

    if (cbinfo->n_added &&
        (bufev->enabled & EV_WRITE) &&
        !bufev_p->write_suspended) {
        /* Somebody added data to the buffer, and we would like to
         * write, and we were not writing.  So, start writing. */
        if (bufferevent_add_event_(&bufev->ev_write, &bufev->timeout_write) == -1) {
            /* Should we log this? */
        }
        bufferevent_utp_flush_to_obfoo(bev_utp);
    }
}

static void bufferevent_utp_readcb(evutil_socket_t fd, short event, void *arg)
{
    bufferevent *bufev = arg;

    EVUTIL_ASSERT(event == EV_TIMEOUT);

    bufferevent_incref_and_lock_(bufev);

    bufferevent_disable(bufev, EV_READ);
    bufferevent_run_eventcb_(bufev, BEV_EVENT_READING | BEV_EVENT_TIMEOUT, 0);

    bufferevent_decref_and_unlock_(bufev);
}

static void bufferevent_utp_writecb(evutil_socket_t fd, short event, void *arg)
{
    bufferevent *bufev = arg;

    EVUTIL_ASSERT(event == EV_TIMEOUT);

    bufferevent_incref_and_lock_(bufev);

    bufferevent_disable(bufev, EV_WRITE);
    bufferevent_run_eventcb_(bufev, BEV_EVENT_WRITING | BEV_EVENT_TIMEOUT, 0);

    bufferevent_decref_and_unlock_(bufev);
}

static void obfoo_output_cb(evbuffer *buf, const evbuffer_cb_info *cbinfo, void *arg)
{
    bufferevent *bufev = arg;
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bufev);
    if (cbinfo->n_added) {
        bufferevent_utp_flush_to_utp(bev_utp);
    }
}

int bufferevent_utp_connect(bufferevent *bev, const sockaddr *sa, int socklen)
{
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bev);
    bufferevent_private *bufev_p = BEV_UPCAST(bev);

    bufferevent_incref_and_lock_(bev);

    int result = -1;
    int ownutp = 0;
    utp_socket *utp = bev_utp->utp;
    if (!utp) {
        if (!sa) {
            goto done;
        }
        utp = utp_create_socket(bev_utp->utp_ctx);
        if (!utp) {
            goto done;
        }
        ownutp = 1;
    }
    if (sa) {
        int r = utp_connect(utp, sa, socklen);
        if (r < 0) {
            goto freesock;
        }
    }
    utp_set_userdata(utp, bev);
    bev_utp->utp = utp;
    if (!be_utp_enable(bev, EV_WRITE)) {
        bev_utp->obfoo->incoming = false;
        obfoo_write_intro(bev_utp->obfoo, bev_utp->obfoo_output);
        bufev_p->connecting = 1;
        result = 0;
        goto done;
    }

    goto done;

freesock:
    if (ownutp) {
        utp_set_userdata(utp, NULL);
        utp_close(utp);
    }
done:
    bufferevent_decref_and_unlock_(bev);
    return result;
}

bufferevent *
bufferevent_utp_new(event_base *base, utp_context *utp_ctx, utp_socket *utp, int options)
{
    bufferevent_utp *bev_utp = mm_calloc(1, sizeof(bufferevent_utp));

    if (!bev_utp) {
        return NULL;
    }

    bufferevent_private *bev_p = &bev_utp->bev;

    bev_utp->utp_ctx = utp_ctx;

    if (bufferevent_init_common_(bev_p, base, &bufferevent_ops_utp, options) < 0) {
        mm_free(bev_utp);
        return NULL;
    }

    bufferevent *bufev = &bev_p->bev;

    if (options & BEV_OPT_THREADSAFE) {
        bufferevent_enable_locking_(bufev, NULL);
    }

    bev_utp->obfoo = obfoo_new();
    bev_utp->obfoo_input = evbuffer_new();
    bev_utp->obfoo_output = evbuffer_new();
    evbuffer_add_cb(bev_utp->obfoo_output, obfoo_output_cb, bufev);
    bev_utp->obfoo->incoming = true;

    if (utp) {
        utp_set_userdata(utp, bufev);
        bev_utp->utp = utp;
    }

    event_assign(&bufev->ev_read, bufev->ev_base, -1,
        EV_PERSIST|EV_FINALIZE, bufferevent_utp_readcb, bufev);
    event_assign(&bufev->ev_write, bufev->ev_base, -1,
        EV_PERSIST|EV_FINALIZE, bufferevent_utp_writecb, bufev);

    evbuffer_add_cb(bufev->output, bufferevent_utp_outbuf_cb, bufev);

    evbuffer_freeze(bufev->input, 0);
    evbuffer_freeze(bufev->output, 1);

    return bufev;
}

utp_socket* bufferevent_get_utp(const bufferevent *bev)
{
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bev);
    bufferevent_private *bufev_p = BEV_UPCAST(bev);
    return bev_utp->utp;
}

static int be_utp_enable(bufferevent *bufev, short event)
{
    if (event & EV_READ &&
        bufferevent_add_event_(&bufev->ev_read, &bufev->timeout_read) == -1) {
        return -1;
    }
    if (event & EV_WRITE &&
        bufferevent_add_event_(&bufev->ev_write, &bufev->timeout_write) == -1) {
        return -1;
    }
    return 0;
}

static int be_utp_disable(bufferevent *bufev, short event)
{
    bufferevent_private *bufev_p = BEV_UPCAST(bufev);
    if (event & EV_READ) {
        if (event_del(&bufev->ev_read) == -1) {
            return -1;
        }
    }
    /* Don't actually disable the write if we are trying to connect. */
    if ((event & EV_WRITE) && ! bufev_p->connecting) {
        if (event_del(&bufev->ev_write) == -1) {
            return -1;
        }
    }
    return 0;
}

static void be_utp_destruct(bufferevent *bufev)
{
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bufev);

    if ((bev_utp->bev.options & BEV_OPT_CLOSE_ON_FREE) && bev_utp->utp != NULL) {
        utp_set_userdata(bev_utp->utp, NULL);
        utp_close(bev_utp->utp);
    }
    evbuffer_free(bev_utp->obfoo_input);
    evbuffer_free(bev_utp->obfoo_output);
    obfoo_free(bev_utp->obfoo);
}

static int be_utp_flush(bufferevent *bev, short iotype,
    enum bufferevent_flush_mode mode)
{
    return 0;
}

static int be_utp_ctrl(bufferevent *bev, enum bufferevent_ctrl_op op,
    union bufferevent_ctrl_data *data)
{
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bev);
    switch (op) {
    case BEV_CTRL_GET_FD:
        data->fd = EVUTIL_INVALID_SOCKET;
        return 0;
    case BEV_CTRL_SET_FD:
        return 0;
    case BEV_CTRL_GET_UNDERLYING:
    case BEV_CTRL_CANCEL_ALL:
    default:
        return -1;
    }
}
