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
#endif

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "utils.h"


#define MAX_OUTPUT (512*1024)

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
			LOGE("error with sock %d: %s", bufferevent_getfd(bev), 
                    (errno ? strerror(errno) : ""));
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
    struct bufferevent *b_in, *b_out; 

    int fd_in, fd_out;

    struct pipe pipe_in_out;
    struct pipe pipe_out_in;

    struct event *in_read;
    struct event *in_write;
    struct event *out_read;
    struct event *out_write;
    int eof_bits;       /* indicate which channel should stop read */
} sock_relay_ctx;

#define IN_OUT_EOF 1
#define OUT_IN_EOF 2
#define BOTH_EOF (OUT_IN_EOF | IN_OUT_EOF)

int init_pipe(struct pipe *p)
{
    p->data = 0;
    int pipefd[2] = {0};

    int rc = pipe2(pipefd, O_NONBLOCK | O_CLOEXEC);
    if (rc == -1)
    {
        perror("pipe2 failed");
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

void sock_relay_ctx_free(sock_relay_ctx *conn)
{
	LOGD("free with EOF bits %x", conn->eof_bits);
	/*event_del(&conn->in_read);
	  event_del(&conn->in_write);
	  event_del(&conn->out_read);
	  event_del(&conn->out_write);*/
	/* event_del() and free resource */
	event_free(conn->in_read);
	event_free(conn->in_write);
	event_free(conn->out_read);
	event_free(conn->out_write);

	fini_pipe(&conn->pipe_in_out);
	fini_pipe(&conn->pipe_out_in);

	bufferevent_free(conn->b_in);
	bufferevent_free(conn->b_out);

	free(conn);
}

#define MAX_DATA_IN_PIPE MAX_OUTPUT

/*
* move from fd to pipe buffer
*/
int socket_to_pipe(sock_relay_ctx *conn, int fd, struct pipe *pipe, size_t *count)
{
    int retval = 0;

    while (*count) {
        int rc = splice(fd, NULL, pipe->produce, NULL, *count, SPLICE_F_MOVE | SPLICE_F_NONBLOCK/* | SPLICE_F_MORE*/);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN) {
                /* there are two reasons for EAGAIN :
                *   - nothing in the socket buffer (standard)
                *   - pipe is full
                *   - the connection is closed (kernel < 2.6.27.13)
                */
                if (pipe->data) {
                    // TODO: maybe pipe full, so stop read
                    break;
                }

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
            *count -= rc;
            pipe->data += rc;

			LOGD("splice read %d bytes from fd %d", rc, fd);

            if (pipe->data > MAX_DATA_IN_PIPE) {
                break;
            }
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
int socket_from_pipe(sock_relay_ctx *conn, int fd, struct pipe *pipe, size_t *count)
{
    int retval = 0;

    while (*count)
    {
        int rc = splice(pipe->consume, NULL, fd, NULL, *count, SPLICE_F_MOVE | SPLICE_F_NONBLOCK/* | SPLICE_F_MORE*/);
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
            *count -= rc;
            pipe->data -= rc;
            retval += rc;

			LOGD("splice write %d bytes to fd %d", rc, fd);
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
    sock_relay_ctx *conn = (sock_relay_ctx*)arg;

    if (events & EV_READ) {
        int in = (fd == conn->fd_in);
        struct pipe *pipe = (in ? &conn->pipe_in_out : &conn->pipe_out_in);
        struct event *ev_write = (in ? conn->out_write : conn->in_write);
        struct event *ev_read = (in ? conn->in_read : conn->out_read);
        int try_write = (pipe->data == 0);
		size_t count = MAX_DATA_IN_PIPE;

        int rc = socket_to_pipe(conn, fd, pipe, &count);
		if (rc < 0) {
            /* stop read when EOF or ERROR */
            event_del(ev_read);
			conn->eof_bits |= (in ? IN_OUT_EOF : OUT_IN_EOF);
			LOGD("set channel EOF bits %x", (in ? IN_OUT_EOF : OUT_IN_EOF));
		}

        if (count > 0 && try_write) {
			count = pipe->data;
            rc = socket_from_pipe(conn, (in ? conn->fd_out : conn->fd_in), pipe, &count);
        }

        if (pipe->data) {
            /* stop read and wait write */
            event_del(ev_read);
            event_add(ev_write, NULL);
        }
    } else if (events | EV_WRITE) {
        int out = (fd == conn->fd_out);
        struct pipe *pipe = (out ? &conn->pipe_in_out : &conn->pipe_out_in);
        struct event *ev_write = (out ? conn->out_write : conn->in_write);
        struct event *ev_read = (out ? conn->in_read : conn->out_read);
		size_t count = pipe->data;

        int rc = socket_from_pipe(conn, fd, pipe, &count);
		if (rc < 0) {
			/* stop write when ERROR */
			event_del(ev_write);
			conn->eof_bits |= (out ? IN_OUT_EOF : OUT_IN_EOF);
			LOGD("set channel EOF bits %x", (out ? IN_OUT_EOF : OUT_IN_EOF));
		}

        if (pipe->data == 0) {
            /* stop write and wait read*/
            event_del(ev_write);
            event_add(ev_read, NULL);
        }
    }

	if (conn->eof_bits & BOTH_EOF) {
		if (BOTH_EOF == (conn->eof_bits & BOTH_EOF)) {
			sock_relay_ctx_free(conn); /* both channel detect error */
		} else if (conn->pipe_in_out.data == 0 && conn->pipe_out_in.data == 0) {
			sock_relay_ctx_free(conn); /* one socket EOF or error, but other channel wait read */
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
            perror("vmsplice error");
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
#ifdef HAVE_SPLICE
    if (use_splice && bufferevent_get_underlying(local) == NULL && bufferevent_get_underlying(remote) == NULL) {
        sock_relay_ctx *conn = calloc(sizeof(sock_relay_ctx), 1);
        assert(conn);

        conn->b_in = local;
        conn->b_out = remote;
        conn->fd_in = bufferevent_getfd(conn->b_in);
        conn->fd_out = bufferevent_getfd(conn->b_out);
        bufferevent_disable(local, EV_READ | EV_WRITE);
        bufferevent_disable(remote, EV_READ | EV_WRITE);

        init_pipe(&conn->pipe_in_out);
        init_pipe(&conn->pipe_out_in);

        struct event_base *base = bufferevent_get_base(conn->b_in);

        // relay input buffer
#define RELAY_BUFFER(from, to)  do { \
            if (evbuffer_get_length(bufferevent_get_input(from)) > 0) { \
                evbuffer_add_buffer(bufferevent_get_output(to), bufferevent_get_input(from)); \
            } \
        } while (0)

        RELAY_BUFFER(local, remote);
        RELAY_BUFFER(remote, local);

        // flush output buffer to pipe;
        if (0 != flush_bufferevent_to_pipe(local, &conn->pipe_out_in) ||
            0 != flush_bufferevent_to_pipe(remote, &conn->pipe_in_out)) {
            goto fail;
        }

        // 
        conn->in_read = event_new(base, conn->fd_in, EV_PERSIST | EV_READ, relaycb, conn);
        conn->in_write = event_new(base, conn->fd_in, EV_PERSIST | EV_WRITE, relaycb, conn);

        conn->out_read = event_new(base, conn->fd_out, EV_PERSIST | EV_READ, relaycb, conn);
        conn->out_write = event_new(base, conn->fd_out, EV_PERSIST | EV_WRITE, relaycb, conn);

        // setup read or write event
        if (conn->pipe_in_out.data) {
            event_add(conn->out_write, NULL);
        } else {
            event_add(conn->in_read, NULL);
        }

        if (conn->pipe_out_in.data) {
            event_add(conn->in_write, NULL);
        } else {
            event_add(conn->out_read, NULL);
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




