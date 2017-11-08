/*
 *   This example code shows how to write an (optionally encrypting) SSL proxy
 *     with Libevent's bufferevent layer.
 *
 *       XXX It's a little ugly and should probably be cleaned up.
 *        */

#ifdef HAVE_SPLICE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "utils.h"


#define MAX_OUTPUT (512*1024)

extern int g_https_proxy;

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

static void
readcb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (!partner) {
		evbuffer_drain(src, len);
		return;
	}
	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);

	if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
		/* We're giving the other side data faster than it can
 * 		 * pass it on.  Stop reading here until we have drained the
 * 		 		 * other side to MAX_OUTPUT/2 bytes. */
		bufferevent_setcb(partner, readcb, drained_writecb,
		    eventcb, bev);
		bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
		    MAX_OUTPUT);
		bufferevent_disable(bev, EV_READ);
	}
}

static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;

	/* We were choking the other side until we drained our outbuf a bit.
 * 	 * Now it seems drained. */
	bufferevent_setcb(bev, readcb, NULL, eventcb, partner);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner)
		bufferevent_enable(partner, EV_READ);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);

	if (evbuffer_get_length(b) == 0) {
		bufferevent_free(bev);
	}
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	struct bufferevent *partner = ctx;

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (what & BEV_EVENT_ERROR) {
			LOGE("bev %p (sock %d) event: %hd, errno: %s", bev, bufferevent_getfd(bev), 
					what, (errno ? strerror(errno) : ""));
		} else {
			LOGD("bev %p (sock %d) event: %hd", bev, bufferevent_getfd(bev), what);
		}

		if (partner) {
			/* Flush all pending data */
			readcb(bev, ctx);

			if (evbuffer_get_length(
				    bufferevent_get_output(partner))) {
				/* We still have to flush data from the other
 * 				 * side, but when that's done, close the other
 * 				 				 * side. */
				bufferevent_setcb(partner,
				    NULL, close_on_finished_writecb,
				    eventcb, NULL);
				bufferevent_disable(partner, EV_READ);
			} else {
				/* We have nothing left to say to the other
 * 				 * side; close it. */
				bufferevent_free(partner);
			}
		}
		bufferevent_free(bev);
	}
	else if (what & BEV_EVENT_CONNECTED){

        }
}

#ifdef HAVE_SPLICE

struct pipe
{
    int data;     /* data length in pipe buffer */
    int produce;  /* pipe, write to */
    int consume;  /* pipe, read from */
};

typedef struct sock_relay_ctx_t
{
	/* defer free, because of BEV_OPT_CLOSE_ON_FREE */
    struct bufferevent *frontend, *backend; 

    int fd_fe, fd_be;

    struct pipe pipe_fe_be;  /* channel: frontend -> pipe -> backend */
    struct pipe pipe_be_fe;  /* channel: backend -> pipe -> frontend */

    struct event *frontend_read;
    struct event *frontend_write;
    struct event *backend_read;
    struct event *backend_write;
    int eof_bits;       /* indicate which channel should stop read */
} sock_relay_ctx;

#define FRONTEND_BACKEND_EOF 1
#define BACKEND_FRONTEND_EOF 2
#define BOTH_EOF (FRONTEND_BACKEND_EOF | BACKEND_FRONTEND_EOF)

int init_pipe(struct pipe *p)
{
    p->data = 0;
    int pipefd[2] = {0};

    int rc = pipe2(pipefd, O_NONBLOCK | O_CLOEXEC);
    if (rc == -1)
    {
        LOGE("pipe2 failed: %s", strerror(errno));
        goto fail;
    }
    else
    {
        p->produce = pipefd[1];
        p->consume = pipefd[0];
        return 0;
    }

fail:
    p->produce = -1;
    p->consume = -1;
    return -1;
}

void fini_pipe(struct pipe *p)
{
    if (p->data)
    {
        LOGE("discard %d pipe data", p->data);
    }

    if (p->produce >= 0)
    {
        close(p->produce);
        p->produce = -1;
    }
    if (p->consume >= 0)
    {
        close(p->consume);
        p->consume = -1;
    }
}

void sock_relay_ctx_free(sock_relay_ctx *ctx)
{
	LOGD("free with EOF bits %x", ctx->eof_bits);

	/* event_del() and free resource */
	event_free(ctx->frontend_read);
	event_free(ctx->frontend_write);
	event_free(ctx->backend_read);
	event_free(ctx->backend_write);

	fini_pipe(&ctx->pipe_fe_be);
	fini_pipe(&ctx->pipe_be_fe);

	bufferevent_free(ctx->frontend);
	bufferevent_free(ctx->backend);

	free(ctx);
}

#define MAX_DATA_IN_PIPE MAX_OUTPUT

/*
* move from fd to pipe buffer
*/
int socket_to_pipe(sock_relay_ctx *ctx, int fd, struct pipe *pipe, size_t *count)
{
    int retval = 0;
    size_t len = *count;

    while (len) {
        int rc = splice(fd, NULL, pipe->produce, NULL, len, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN) {
                /* there are two reasons for EAGAIN :
                *   - nothing in the socket buffer (standard)
                *   - pipe is full
                *   - the connection is closed (kernel < 2.6.27.13)
                */

                break;
            } else {
				LOGE("splice error with sock %d: %s", fd, strerror(errno));
                goto fail;
            }
        } else if (rc == 0) {
            // fd end of file (kernel >= 2.6.27.13)
            LOGD("splice %d EOF", fd);
            goto eof;

        } else {
            retval += rc;
            len -= rc;
            pipe->data += rc;

			LOGD("splice read %d bytes from fd %d", rc, fd);

                break;
        }
    }

	*count = retval;
    return 0;

eof:
fail:
	*count = retval;
	return -1;
}

/*
* move from pipe buffer to out_fd
*/
int socket_from_pipe(sock_relay_ctx *ctx, int fd, struct pipe *pipe, size_t *count)
{
    int retval = 0;
    size_t len = *count;

    while (len)
    {
        int rc = splice(pipe->consume, NULL, fd, NULL, len, SPLICE_F_MOVE | SPLICE_F_NONBLOCK/* | SPLICE_F_MORE*/);
        if (rc <= 0) {
            if (rc == 0 || errno == EAGAIN) {
                break;
            } else if (errno == EINTR) {
                continue;
            } else {
				LOGE("splice error with sock %d: %s", fd, strerror(errno));
                goto fail;
            }
        } else {
            len -= rc;
            pipe->data -= rc;
            retval += rc;

			LOGD("splice write %d bytes to fd %d", rc, fd);
            break;
        }
    }

	*count = retval;
    return retval;

fail:
	*count = retval;
	return -1;
}

static void relaycb(evutil_socket_t fd, short events, void *arg)
{
    sock_relay_ctx *ctx = (sock_relay_ctx*)arg;

    if (events & EV_READ) {
        int to_be = (fd == ctx->fd_fe);
        struct pipe *pipe = (to_be ? &ctx->pipe_fe_be : &ctx->pipe_be_fe);
        struct event *ev_write = (to_be ? ctx->backend_write : ctx->frontend_write);
        struct event *ev_read = (to_be ? ctx->frontend_read : ctx->backend_read);

        int try_write = (pipe->data == 0);
		size_t count = MAX_DATA_IN_PIPE;

        int rc = socket_to_pipe(ctx, fd, pipe, &count);
		if (rc < 0) {
            /* stop read when EOF or ERROR */
            event_del(ev_read);
            int eof = (to_be ? FRONTEND_BACKEND_EOF : BACKEND_FRONTEND_EOF);
			ctx->eof_bits |= eof;
			LOGD("set channel EOF bits %x", eof);
		}

        if (count > 0 && try_write) {
			count = pipe->data;
            rc = socket_from_pipe(ctx, (to_be ? ctx->fd_be : ctx->fd_fe), pipe, &count);
        }

        if (pipe->data) {
            /* stop read and wait write */
            event_del(ev_read);
            event_add(ev_write, NULL);
        }
    } else if (events | EV_WRITE) {
        int to_be = (fd == ctx->fd_be);
        struct pipe *pipe = (to_be ? &ctx->pipe_fe_be : &ctx->pipe_be_fe);
        struct event *ev_write = (to_be ? ctx->backend_write : ctx->frontend_write);
        struct event *ev_read = (to_be ? ctx->frontend_read : ctx->backend_read);

		size_t count = pipe->data;

        int rc = socket_from_pipe(ctx, fd, pipe, &count);
		if (rc < 0) {
			/* stop write when ERROR */
			event_del(ev_write);
            int eof = (to_be ? FRONTEND_BACKEND_EOF : BACKEND_FRONTEND_EOF);
			ctx->eof_bits |= eof;
			LOGD("set channel EOF bits %x", eof);
		}

        if (pipe->data == 0) {
            /* stop write and wait read*/
            event_del(ev_write);
            event_add(ev_read, NULL);
        }
    }

	if (ctx->eof_bits & BOTH_EOF) {
		if (BOTH_EOF == (ctx->eof_bits & BOTH_EOF)) {
			sock_relay_ctx_free(ctx); /* both channel detect error */
		} else if (ctx->pipe_fe_be.data == 0 && ctx->pipe_be_fe.data == 0) {
			sock_relay_ctx_free(ctx); /* one socket EOF or error, but other channel wait read */
		}
	}
}

static int use_splice = 1;

int flush_bufferevent_to_pipe(struct bufferevent *bev, struct pipe *pipe)
{
    struct evbuffer *evbuf = bufferevent_get_output(bev);
    int len = evbuffer_get_length(evbuf);
    if (len > 0) {
        int iovec_len = evbuffer_peek(evbuf, -1, NULL, NULL, 0);

        struct iovec iov[iovec_len];

        evbuffer_peek(evbuf, -1, NULL, iov, iovec_len);

        ssize_t rc = vmsplice(pipe->produce, iov,
            iovec_len, SPLICE_F_NONBLOCK);
        if (rc < 0) {
            LOGE("vmsplice error: %s", strerror(errno));
            return -1;
        }
        else if (rc != len)
        {
            LOGE("too long to fit pipe buffer");
            return -1;
        }

        // ok
        evbuffer_drain(evbuf, len);
        pipe->data += len;
    }

    return 0;
}
#endif

/*
 * local/frontend/
 * remote/backend/upstream
 */
void
relay(struct bufferevent *local, struct bufferevent *remote)
{
    LOGD("relay bev %p <--> %p", local, remote);
#ifdef HAVE_SPLICE
    if (use_splice && !g_https_proxy && bufferevent_get_underlying(remote) == NULL) {
        sock_relay_ctx *conn = calloc(sizeof(sock_relay_ctx), 1);
        assert(conn);

        conn->frontend = local;
        conn->backend = remote;
        conn->fd_fe = bufferevent_getfd(conn->frontend);
        conn->fd_be = bufferevent_getfd(conn->backend);
        bufferevent_disable(local, EV_READ | EV_WRITE);
        bufferevent_disable(remote, EV_READ | EV_WRITE);

        if (-1 == init_pipe(&conn->pipe_fe_be) ||
            -1 == init_pipe(&conn->pipe_be_fe)) {
            goto fail;
        }

        struct event_base *base = bufferevent_get_base(conn->frontend);

        // relay input buffer
#define RELAY_BUFFER(from, to)  do { \
            if (evbuffer_get_length(bufferevent_get_input(from)) > 0) { \
                evbuffer_add_buffer(bufferevent_get_output(to), bufferevent_get_input(from)); \
            } \
        } while (0)

        RELAY_BUFFER(local, remote);
        RELAY_BUFFER(remote, local);

        // flush output buffer to pipe;
        if (0 != flush_bufferevent_to_pipe(local, &conn->pipe_be_fe) ||
            0 != flush_bufferevent_to_pipe(remote, &conn->pipe_fe_be)) {
            goto fail;
        }

        // 
        conn->frontend_read = event_new(base, conn->fd_fe, EV_PERSIST | EV_READ, relaycb, conn);
        conn->frontend_write = event_new(base, conn->fd_fe, EV_PERSIST | EV_WRITE, relaycb, conn);

        conn->backend_read = event_new(base, conn->fd_be, EV_PERSIST | EV_READ, relaycb, conn);
        conn->backend_write = event_new(base, conn->fd_be, EV_PERSIST | EV_WRITE, relaycb, conn);

        // setup read or write event
        if (conn->pipe_fe_be.data) {
            event_add(conn->backend_write, NULL);
        } else {
            event_add(conn->frontend_read, NULL);
        }

        if (conn->pipe_be_fe.data) {
            event_add(conn->frontend_write, NULL);
        } else {
            event_add(conn->backend_read, NULL);
        }

		return;

    fail:
        sock_relay_ctx_free(conn);
    } else 
#endif
    {
        bufferevent_setcb(local, readcb, NULL, eventcb, remote);
        bufferevent_setcb(remote, readcb, NULL, eventcb, local);

        bufferevent_enable(local, EV_READ | EV_WRITE);
        bufferevent_enable(remote, EV_READ | EV_WRITE);
    }
}




