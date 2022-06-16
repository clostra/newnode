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


// utp_read > obin > bevin
// bevout > obout > utp_write


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

typedef struct {
    bufferevent_private bev;
    utp_context *utp_ctx;
    utp_socket *utp;
    obfoo *obfoo;
    evbuffer *obfoo_input;
    evbuffer *obfoo_output;
    evutil_socket_t fake_fd;
    bool utp_writable:1;
} bufferevent_utp;

static int be_utp_enable(bufferevent *, short);
static int be_utp_disable(bufferevent *, short);
static void be_utp_destruct(bufferevent *);
static int be_utp_flush(bufferevent *, short, enum bufferevent_flush_mode);
static int be_utp_ctrl(bufferevent *, enum bufferevent_ctrl_op, union bufferevent_ctrl_data *);

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
    size_t num_iovecs = 0;
    utp_iovec iovecs[UTP_IOV_MAX] = {};
    evbuffer_ptr ptr;
    evbuffer_ptr_set(buffer, &ptr, 0, EVBUFFER_PTR_SET);
    evbuffer_iovec v;
    while (num_iovecs < lenof(iovecs) && evbuffer_peek(buffer, -1, &ptr, &v, 1) > 0) {
        iovecs[num_iovecs].iov_base = v.iov_base;
        iovecs[num_iovecs].iov_len = v.iov_len;
        num_iovecs++;
        if (evbuffer_ptr_set(buffer, &ptr, v.iov_len, EVBUFFER_PTR_ADD) < 0) {
            break;
        }
    }
    if (!num_iovecs) {
        return 0;
    }
    ssize_t r = utp_writev(utp, iovecs, num_iovecs);
    if (r < 0) {
        return -1;
    }
    evbuffer_drain(buffer, r);
    return r;
}

static void bufferevent_utp_event(bufferevent *bufev, short what, int error)
{
    short ev_what = (what & BEV_EVENT_READING ? EV_READ : 0) | (what & BEV_EVENT_WRITING ? EV_WRITE : 0);
    if (bufev->enabled & ev_what) {
        EVUTIL_SET_SOCKET_ERROR(error);
        if (ev_what & EV_READ) {
            bufferevent_disable(bufev, EV_READ);
        }
        if (ev_what & EV_WRITE) {
            bufferevent_disable(bufev, EV_WRITE);
        }
        bufferevent_run_eventcb_(bufev, what, 0);
        return;
    }
    bufferevent_private *bufev_p = BEV_UPCAST(bufev);
    bufev_p->eventcb_pending |= what;
    bufev_p->errno_pending = error;
}

static void bufferevent_utp_bevout_to_obout(bufferevent_utp *bev_utp)
{
    bufferevent_private *bufev_p = &bev_utp->bev;

    if (bufev_p->write_suspended) {
        return;
    }

    bufferevent *bufev = &bufev_p->bev;
    assert(bufev->enabled & EV_WRITE);

    ssize_t res = 0;
    if (evbuffer_get_length(bufev->output)) {
        ev_ssize_t atmost = bufferevent_get_write_max_(bufev_p);

        evbuffer_unfreeze(bufev->output, 1);
        // XXX: observe "atmost" to support rate-limiting
        res = obfoo_output_filter(bev_utp->obfoo, bufev->output, bev_utp->obfoo_output);
        evbuffer_freeze(bufev->output, 1);

        if (res == -1) {
            bufferevent_utp_event(bufev, BEV_EVENT_ERROR | BEV_EVENT_WRITING, ENOBUFS);
            return;
        }

        bufferevent_decrement_write_buckets_(bufev_p, res);
    }

    if (evbuffer_get_length(bufev->output) == 0) {
        BEV_DEL_GENERIC_WRITE_TIMEOUT(bufev);
    }

    /*
     * Invoke the user callback if our buffer is drained or below the
     * low watermark.
     */
    if (res) {
        bufferevent_trigger_nolock_(bufev, EV_WRITE, 0);
    }
}

static void bufferevent_utp_obout_to_utp(bufferevent_utp *bev_utp)
{
    if (!bev_utp->utp_writable) {
        return;
    }
    bufferevent *bufev = &bev_utp->bev.bev;
    evbuffer_unfreeze(bev_utp->obfoo_output, 1);
    ssize_t len = evbuffer_get_length(bev_utp->obfoo_output);
    ssize_t fres = evbuffer_utp_write(bev_utp->obfoo_output, bev_utp->utp);
    evbuffer_freeze(bev_utp->obfoo_output, 1);
    if (len != fres) {
        bev_utp->utp_writable = false;
    }
    if (fres == -1) {
        bufferevent_utp_event(bufev, BEV_EVENT_ERROR | BEV_EVENT_WRITING, EINVAL);
    }
}

const char* utp_state(int state)
{
    switch (state) {
    case UTP_STATE_CONNECT: return "UTP_STATE_CONNECT";
    case UTP_STATE_WRITABLE : return "UTP_STATE_WRITABLE";
    case UTP_STATE_EOF: return "UTP_STATE_EOF";
    case UTP_STATE_DESTROYING : return "UTP_STATE_DESTROYING";
    default:
    case -1: assert(false);
    }
    return "unknown";
}

uint64 utp_on_state_change(utp_callback_arguments *a)
{
    bufferevent *bufev = (bufferevent*)utp_get_userdata(a->socket);

    if (!bufev) {
        return 0;
    }

    bufferevent_private *bufev_p = BEV_UPCAST(bufev);
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bufev);

    switch (a->state) {
    case UTP_STATE_CONNECT:
        bufev_p->connecting = 0;
        bufferevent_socket_set_conn_address_utp_(bufev, bev_utp->utp);
        bufferevent_run_eventcb_(bufev, BEV_EVENT_CONNECTED, 0);
        if (!(bufev->enabled & EV_WRITE) || bufev_p->write_suspended) {
            BEV_DEL_GENERIC_WRITE_TIMEOUT(bufev);
        } else {
            BEV_RESET_GENERIC_WRITE_TIMEOUT(bufev);
        }
    case UTP_STATE_WRITABLE:
        bev_utp->utp_writable = true;
        bufferevent_utp_obout_to_utp(bev_utp);
        break;
    case UTP_STATE_EOF:
        bufferevent_utp_event(bufev, BEV_EVENT_EOF | BEV_EVENT_READING, 0);
        break;
    case UTP_STATE_DESTROYING:
        bev_utp->utp = NULL;
        bev_utp->utp_writable = false;
        break;
    }

    return 0;
}

static void bufferevent_utp_close(bufferevent_utp *bev_utp)
{
    utp_set_userdata(bev_utp->utp, NULL);
    utp_close(bev_utp->utp);
    bev_utp->utp = NULL;
    bev_utp->utp_writable = false;
}

uint64 utp_on_error(utp_callback_arguments *a)
{
    bufferevent_utp *bev_utp = utp_get_userdata(a->socket);

    if (!bev_utp) {
        return 0;
    }

    bufferevent *bufev = &bev_utp->bev.bev;

    int error;
    switch (a->error_code) {
    case UTP_ECONNREFUSED: error = ECONNREFUSED; break;
    case UTP_ECONNRESET: error = ECONNRESET; break;
    case UTP_ETIMEDOUT: error = ETIMEDOUT; break;
    default:
    case -1: error = EINVAL; break;
    }

    bufferevent_utp_close(bev_utp);
    bufferevent_utp_event(bufev, BEV_EVENT_ERROR | BEV_EVENT_WRITING, error);
    return 0;
}

static void bufferevent_utp_obin_to_bevin(bufferevent_utp *bev_utp)
{
    bufferevent *bufev = &bev_utp->bev.bev;

    assert(bufev->enabled & EV_READ);

    BEV_RESET_GENERIC_READ_TIMEOUT(bufev);

    of_state s = bev_utp->obfoo->state;

    evbuffer_unfreeze(bufev->input, 0);
    ssize_t fres = obfoo_input_filter(bev_utp->obfoo, bev_utp->obfoo_input, bufev->input, bev_utp->obfoo_output);
    evbuffer_freeze(bufev->input, 0);

    if (fres < 0) {
        bufferevent_utp_event(bufev, BEV_EVENT_ERROR | BEV_EVENT_READING, ENOBUFS);
        return;
    }

    bufferevent_private *bufev_p = &bev_utp->bev;
    bufferevent_decrement_read_buckets_(bufev_p, fres);

    if (s < OF_STATE_DISCARD && bev_utp->obfoo->state >= OF_STATE_DISCARD) {
        // writing is now possible, flush
        if (bufev->enabled & EV_WRITE) {
            bufferevent_utp_bevout_to_obout(bev_utp);
        }
    }

    if (fres) {
        bufferevent_trigger_nolock_(bufev, EV_READ, 0);
    }
}

uint64 utp_on_read(utp_callback_arguments *a)
{
    bufferevent_utp *bev_utp = utp_get_userdata(a->socket);
    bufferevent *bufev = &bev_utp->bev.bev;

    BEV_RESET_GENERIC_READ_TIMEOUT(bufev);

    evbuffer_unfreeze(bev_utp->obfoo_input, 0);
    int res = evbuffer_add(bev_utp->obfoo_input, a->buf, a->len);
    evbuffer_freeze(bev_utp->obfoo_input, 0);

    if (res == -1) {
        bufferevent_utp_event(bufev, BEV_EVENT_ERROR | BEV_EVENT_READING, ENOBUFS);
        return 0;
    }

    if (bufev->enabled & EV_READ) {
        bufferevent_utp_obin_to_bevin(bev_utp);
    }

    return 0;
}

static void bufferevent_utp_bevout_cb(evbuffer *buf, const evbuffer_cb_info *cbinfo, void *arg)
{
    bufferevent_utp *bev_utp = arg;
    bufferevent_private *bufev_p = &bev_utp->bev;
    bufferevent *bufev = &bev_utp->bev.bev;

    if (cbinfo->n_added &&
        (bufev->enabled & EV_WRITE) &&
        !bufev_p->write_suspended) {
        /* Somebody added data to the buffer, and we would like to
         * write, and we were not writing.  So, start writing. */
        BEV_RESET_GENERIC_WRITE_TIMEOUT(bufev);
        bufferevent_utp_bevout_to_obout(bev_utp);
    }
}

static void obfoo_output_cb(evbuffer *buf, const evbuffer_cb_info *cbinfo, void *arg)
{
    bufferevent_utp *bev_utp = arg;
    if (cbinfo->n_added) {
        bufferevent_utp_obout_to_utp(bev_utp);
    }
}

int bufferevent_utp_connect(bufferevent *bev, const sockaddr *sa, int socklen)
{
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bev);

    int result = -1;
    bool ownutp = false;
    utp_socket *utp = bev_utp->utp;
    if (!utp) {
        if (!sa) {
            return result;
        }
        utp = utp_create_socket(bev_utp->utp_ctx);
        if (!utp) {
            return result;
        }
        ownutp = true;
    }
    if (sa) {
        if (utp_connect(utp, sa, socklen) < 0) {
            if (ownutp) {
                utp_close(utp);
            }
            return result;
        }
    }
    utp_set_userdata(utp, bev);
    bev_utp->utp = utp;
    if (!be_utp_enable(bev, EV_WRITE)) {
        bev_utp->obfoo->incoming = false;
        obfoo_write_intro(bev_utp->obfoo, bev_utp->obfoo_output);
        bufferevent_private *bufev_p = &bev_utp->bev;
        bufev_p->connecting = 1;
        result = 0;
    }
    return result;
}

bufferevent* bufferevent_utp_new(event_base *base, utp_context *utp_ctx, utp_socket *utp, int options)
{
    bufferevent_utp *bev_utp = mm_calloc(1, sizeof(bufferevent_utp));

    if (!bev_utp) {
        return NULL;
    }

    bev_utp->utp_ctx = utp_ctx;

    bufferevent_private *bev_p = &bev_utp->bev;
    if (bufferevent_init_common_(bev_p, base, &bufferevent_ops_utp, options) < 0) {
        mm_free(bev_utp);
        return NULL;
    }

    bev_utp->fake_fd = EVUTIL_INVALID_SOCKET;

    bev_utp->obfoo = obfoo_new();
    bev_utp->obfoo_input = evbuffer_new();
    bev_utp->obfoo_output = evbuffer_new();
    bev_utp->obfoo->incoming = true;
    evbuffer_add_cb(bev_utp->obfoo_output, obfoo_output_cb, bev_utp);

    evbuffer_freeze(bev_utp->obfoo_input, 0);
    evbuffer_freeze(bev_utp->obfoo_output, 1);

    if (utp) {
        utp_set_userdata(utp, bev_utp);
        bev_utp->utp = utp;
    }

    bufferevent *bufev = &bev_p->bev;
    bufferevent_init_generic_timeout_cbs_(bufev);

    evbuffer_add_cb(bufev->output, bufferevent_utp_bevout_cb, bev_utp);

    evbuffer_freeze(bufev->input, 0);
    evbuffer_freeze(bufev->output, 1);

    return bufev;
}

utp_socket* bufferevent_get_utp(const bufferevent *bev)
{
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bev);
    return bev_utp->utp;
}

static int be_utp_enable(bufferevent *bufev, short event)
{
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bufev);

    if (event & EV_READ) {
        BEV_RESET_GENERIC_READ_TIMEOUT(bufev);
        bufferevent_utp_obin_to_bevin(bev_utp);
    }
    if (event & EV_WRITE) {
        BEV_RESET_GENERIC_WRITE_TIMEOUT(bufev);
        bufferevent_utp_bevout_to_obout(bev_utp);
    }
    bufferevent_private *bufev_p = &bev_utp->bev;
    short bev_what = (event & EV_READ ? BEV_EVENT_READING : 0) | (event & EV_WRITE ? BEV_EVENT_WRITING : 0);
    if (bufev_p->eventcb_pending & bev_what) {
        EVUTIL_SET_SOCKET_ERROR(bufev_p->errno_pending);
        if (bufev_p->eventcb_pending & BEV_EVENT_READING) {
            bufferevent_disable(bufev, EV_READ);
        }
        if (bufev_p->eventcb_pending & BEV_EVENT_WRITING) {
            bufferevent_disable(bufev, EV_WRITE);
        }
        bufferevent_run_eventcb_(bufev, bufev_p->eventcb_pending, BEV_OPT_DEFER_CALLBACKS);
    }
    return 0;
}

static int be_utp_disable(bufferevent *bufev, short event)
{
    if (event & EV_READ) {
        BEV_DEL_GENERIC_READ_TIMEOUT(bufev);
    }
    /* Don't actually disable the write if we are trying to connect. */
    bufferevent_private *bufev_p = BEV_UPCAST(bufev);
    if ((event & EV_WRITE) && !bufev_p->connecting) {
        BEV_DEL_GENERIC_WRITE_TIMEOUT(bufev);
    }
    return 0;
}

static void be_utp_destruct(bufferevent *bufev)
{
    bufferevent_utp *bev_utp = bufferevent_utp_upcast(bufev);

    if ((bev_utp->bev.options & BEV_OPT_CLOSE_ON_FREE) && bev_utp->utp) {
        bufferevent_utp_close(bev_utp);
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
        data->fd = bev_utp->fake_fd;
        return 0;
    case BEV_CTRL_SET_FD:
        bev_utp->fake_fd = data->fd;
        // I don't agree with this hack, but we need it for the same reason bufferevent_sock does
        // https://github.com/libevent/libevent/commit/255525dd741df04f8497396b8035c5d2bdabd269
        evbuffer_unfreeze(bev->input, 0);
        evbuffer_unfreeze(bev->output, 1);
        return 0;
    case BEV_CTRL_GET_UNDERLYING:
    case BEV_CTRL_CANCEL_ALL:
    default:
        return -1;
    }
}
