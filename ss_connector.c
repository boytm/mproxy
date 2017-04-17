#ifdef ENABLE_SS
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef _WIN32
# include <malloc.h>
#endif

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "connector.h"

#undef HAVE_CONFIG_H
#include "encrypt.h"
#include "utils.h"

#ifdef _MSC_VER
#define alloca _alloca
#endif

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

static void free_context(void *ctx)
{
	ss_conn *conn = (ss_conn*)ctx;

    cipher_context_release(&conn->e_ctx.evp);
    cipher_context_release(&conn->d_ctx.evp);

	free(conn);
}

static enum bufferevent_filter_result input_filter(struct evbuffer *src, struct evbuffer *dst, ev_ssize_t dst_limit, enum bufferevent_flush_mode mode, void *ctx)
{
	int i;
	ss_conn *conn = (ss_conn*)ctx;

#define CRYPT(method, crypt_ctx, extra_len) \
	do { \
		int iovec_len = evbuffer_peek(src, -1, NULL, NULL, 0); \
 \
		struct evbuffer_iovec *vec_src = alloca(sizeof(struct evbuffer_iovec) * iovec_len); \
		struct evbuffer_iovec vec_dst[1]; \
 \
		evbuffer_peek(src, -1, NULL, vec_src, iovec_len); \
		if (1 != evbuffer_reserve_space(dst, evbuffer_get_length(src) + (extra_len), vec_dst, 1)) { \
			/* malloc space failed */ \
			return BEV_ERROR; \
		} \
		vec_dst[0].iov_len = 0; \
 \
		for (i = 0; i < iovec_len; i++)	{ \
			ssize_t r = vec_src[i].iov_len; \
			char *buf = ss_ ## method((char*)vec_dst[0].iov_base + vec_dst[0].iov_len, vec_src[i].iov_base, &r, &(crypt_ctx)); \
			if (!buf) { \
				/* crypt error */ \
				LOGE( # method " failed"); \
				return BEV_ERROR; \
			} \
 \
			vec_dst[0].iov_len += r; \
		} \
 \
		evbuffer_drain(src, -1); \
		if (-1 == evbuffer_commit_space(dst, vec_dst, 1)) { \
			LOGE("evbuffer commit space failed"); \
			return BEV_ERROR; \
		} \
	} while(0)

    CRYPT(decrypt, conn->d_ctx, BLOCK_SIZE);

	return BEV_OK;
}

static enum bufferevent_filter_result output_filter(struct evbuffer *src, struct evbuffer *dst, ev_ssize_t dst_limit, enum bufferevent_flush_mode mode, void *ctx)
{
	int i;
	ss_conn *conn = (ss_conn*)ctx;

	/*{
		int iovec_len = evbuffer_peek(src, -1, NULL, NULL, 0);

		struct evbuffer_iovec vec_src[iovec_len];
		struct evbuffer_iovec vec_dst[1];

		evbuffer_peek(src, -1, NULL, vec_src, iovec_len);
		if (1 != evbuffer_reserve_space(dst, evbuffer_get_length(src) + MAX_IV_LENGTH + BLOCK_SIZE, vec_dst, 1)) {
			// malloc space failed
			return BEV_ERROR;
		}
		vec_dst[0].iov_len = 0;

		for (i = 0; i < iovec_len; i++)
		{
			ssize_t r = vec_src[i].iov_len;
			char *buf = ss_encrypt((char*)vec_dst[0].iov_base + vec_dst[0].iov_len, vec_src[i].iov_base, &r, &conn->e_ctx);
			if (!buf) {
				// crypt error
				LOGE("ss_encrypt failed");
				return BEV_ERROR;
			}

			vec_dst[0].iov_len += r;
		}

		evbuffer_drain(src, -1);
		if (-1 == evbuffer_commit_space(dst, vec_dst, 1)) {
			return BEV_ERROR;
		}
	}*/
    CRYPT(encrypt, conn->e_ctx, MAX_IV_LENGTH + BLOCK_SIZE);

	return BEV_OK;
}

static void ss_eventcb(struct bufferevent *bev, short what, void *ctx)
{
    struct bufferevent *bev_filter = NULL;
	ss_conn *conn = (ss_conn*)ctx;
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		// during handshake, EOF is an error also
		LOGE("bev %p (sock %d) event: %hd", bev, bufferevent_getfd(bev), what);

		// error
		conn->cb(NULL, conn->arg);

		free_context(conn);
        bufferevent_free(bev);
	} else if (what & BEV_EVENT_CONNECTED) {
		LOGD("upstrem connected with bev %p (sock %d)", bev, bufferevent_getfd(bev));

		/* TCP */
		bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

		/* ss */
		enc_ctx_init(g_ss_method, &conn->e_ctx, 1);
		enc_ctx_init(g_ss_method, &conn->d_ctx, 0);

        /* any changes in output evbuffer will call output_filter, so must be deferred */
        bev_filter = bufferevent_filter_new(bev, input_filter, output_filter, BEV_OPT_CLOSE_ON_FREE/*|BEV_OPT_DEFER_CALLBACKS*/, free_context, ctx);

        if (bev_filter) {
			LOGD("create filter bev %p from bev %p ", bev_filter, bev);

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
            evbuffer_defer_callbacks(bufferevent_get_output(bev_filter), bufferevent_get_base(bev_filter));
            bufferevent_write(bev_filter, data, 1 + 1 + domain_len + 2);

            conn->cb(bev_filter, conn->arg);
		} else {
			LOGE("create filter event failed");
            conn->cb(bev_filter, conn->arg);

			free_context(conn);
            bufferevent_free(bev);
		}
	}
}

void connect_ss(struct event_base *evbase, struct evdns_base *evdns_base, const char *hostname, int port, connect_callback cb, void *arg)
{
	struct bufferevent *bev = NULL;
	ss_conn *conn = (ss_conn*)calloc(1, sizeof(ss_conn));
    if (NULL == conn) {
        goto fail;
    }

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
	LOGE("connect host %s:%d failed", hostname, port);
	if (bev)
		bufferevent_free(bev);
	cb(NULL, arg);
	if (conn)
		free_context(conn);
}

#endif
