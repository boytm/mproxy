#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "connector.h"

#undef HAVE_CONFIG_H
#include "encrypt.h"
#include "utils.h"

void FATAL(const char *msg)
{
	LOGE("%s", msg);
	exit(-1);
}

/*
 * ss_conn
 */
typedef struct ss_conn_t {
	struct bufferevent *client;

	struct enc_ctx e_ctx;
	struct enc_ctx d_ctx;

	//enum socks5_conn_status status;

	char host[256];
	uint16_t port;
	connect_callback cb;
	void *arg;
} ss_conn;


int g_ss_method;
const char *g_ss_server;
int g_ss_port;
char *g_ss_key;

#define BUF_SIZE (r)

static void free_context(void *ctx)
{
	ss_conn *conn = (ss_conn*)ctx;

	//if (conn->e_ctx != NULL) {
		cipher_context_release(&conn->e_ctx.evp);
		//free(conn->e_ctx);
	//}
	//if (conn->d_ctx != NULL) {
		cipher_context_release(&conn->d_ctx.evp);
		//free(conn->d_ctx);
	//}

	free(conn);
}

static void cleanupfn(const void *data, size_t datalen, void *extra)
{
	free((void *)data);
}

static enum bufferevent_filter_result input_filter(struct evbuffer *src, struct evbuffer *dst, ev_ssize_t dst_limit, enum bufferevent_flush_mode mode, void *ctx)
{
	int i;
	ss_conn *conn = (ss_conn*)ctx;

	{
		int iovec_len = evbuffer_peek(src, -1, NULL, NULL, 0);

		struct evbuffer_iovec vec_out[iovec_len];

		evbuffer_peek(src, -1, NULL, vec_out, iovec_len);

		for (i = 0; i < iovec_len; i++)
		{
			ssize_t r = vec_out[i].iov_len;
			char *buf = ss_decrypt(BUF_SIZE, vec_out[i].iov_base, &r, &conn->d_ctx);
			if (!buf) {
				// crypt error
				return BEV_ERROR;
			}

			evbuffer_add_reference(dst,	buf, r, cleanupfn, NULL);
		}

		evbuffer_drain(src, -1);
	}

	return BEV_OK;
}

static enum bufferevent_filter_result output_filter(struct evbuffer *src, struct evbuffer *dst, ev_ssize_t dst_limit, enum bufferevent_flush_mode mode, void *ctx)
{
	int i;
	ss_conn *conn = (ss_conn*)ctx;

	{
		int iovec_len = evbuffer_peek(src, -1, NULL, NULL, 0);

		struct evbuffer_iovec vec_out[iovec_len];

		evbuffer_peek(src, -1, NULL, vec_out, iovec_len);

		for (i = 0; i < iovec_len; i++)
		{
			ssize_t r = vec_out[i].iov_len;
			char *buf = ss_encrypt(BUF_SIZE, vec_out[i].iov_base, &r, &conn->e_ctx);
			if (!buf) {
				// crypt error
				return BEV_ERROR;
			}

			evbuffer_add_reference(dst,	buf, r, cleanupfn, NULL);
		}

		evbuffer_drain(src, -1);
	}

	return BEV_OK;
}

static void ss_eventcb(struct bufferevent *bev, short what, void *ctx)
{
	ss_conn *conn = (ss_conn*)ctx;
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		fprintf(stderr, "sock %d error\n", bufferevent_getfd(bev));

		// error
		conn->cb(NULL, conn->arg);

		free_context(conn);
	} else if (what & BEV_EVENT_CONNECTED) {
		fprintf(stderr, "connected with sock %d\n", bufferevent_getfd(bev));

		/* TCP */
		bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

		/* ss */
		enc_ctx_init(g_ss_method, &conn->e_ctx, 1);
		enc_ctx_init(g_ss_method, &conn->d_ctx, 0);

        /* any changes in output evbuffer will call output_filter, so must be defered */
		bev = bufferevent_filter_new(bev, input_filter, output_filter, BEV_OPT_CLOSE_ON_FREE/*|BEV_OPT_DEFER_CALLBACKS*/, free_context, ctx);

		if (bev) {
			/* same as SOCKS5 Requests
			+------+----------+----------+
			| ATYP | DST.ADDR | DST.PORT |
			+------+----------+----------+
			|  1   | Variable |    2     |
			+------+----------+----------+
			*/
			char data[1 + 1 + 255 + 2] = {0x03, };  // DOMAINNAME: X'03
			size_t domain_len = strlen(conn->host);
			assert(domain_len <= 255);
			uint16_t net_port = htons(conn->port);

			data[1] = domain_len;
			memcpy(data + 2, conn->host, domain_len);
			memcpy(data + 2 + domain_len, &net_port, 2);

            /* currently BEV_OPT_DEFER_CALLBACKS no effect with bufferevent_filter_new(), so defer it manually */
            evbuffer_defer_callbacks(bufferevent_get_output(bev), bufferevent_get_base(bev));
			bufferevent_write(bev, data, 1 + 1 + domain_len + 2);
		} else {
			fprintf(stderr, "create filter event failed with sock %d\n", bufferevent_getfd(bev));
			free_context(conn);
		}

		conn->cb(bev, conn->arg);
	}
}

void connect_ss(struct event_base *evbase, struct evdns_base *evdns_base, const char *hostname, int port, connect_callback cb, void *arg)
{
	struct bufferevent *bev = NULL;
	ss_conn *conn = (ss_conn*)calloc(1, sizeof(ss_conn));

	strcpy(conn->host, hostname);
	conn->port = port;
	conn->cb = cb;
	conn->arg = arg;

	//if (g_socks_server && g_socks_port != 0) {
		hostname = g_ss_server;
		port =g_ss_port;

		//conn->status = SCONN_INIT;
	//}

	bev = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE/*|BEV_OPT_DEFER_CALLBACKS*/);
	if (NULL == bev) {
		goto fail;
	}
	if (bufferevent_socket_connect_hostname(bev, evdns_base, PF_UNSPEC, hostname, port) < 0) {
		goto fail;
	}

	bufferevent_setcb(bev, NULL, NULL, ss_eventcb, conn);

	conn->client = bev;
	return;

fail:
	perror("bufferevent_socket_connect");
	if (bev)
		bufferevent_free(bev);
	cb(NULL, arg);
	if (conn)
		free_context(conn);
}


