#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <assert.h>
#include <stdint.h>

#include <event2/dns.h>
#include <event2/event.h>
#include <stdio.h>


extern const char *g_socks_server;
extern int g_socks_port;

typedef void (*connect_callback)(struct bufferevent *bev, void *arg);

const char *socks5_strstatus[] = {
	"ok",
	"server failure",
	"connection not allowed by ruleset",
	"network unreachable",
	"host unreachable",
	"connection refused",
	"TTL expired",
	"command not supported",
	"address type not supported",
};

enum socks5_conn_status {
	SCONN_INIT = 100,
	SCONN_AUTH_METHODS_SENT,
	SCONN_REQUEST_SENT,
	SCONN_CONNECT_TRANSMITTING,
	SCONN_ERROR
};

#define SOCKS5_AUTH_NONE			(0x00)
#define SOCKS5_AUTH_UNACCEPTABLE	(0xFF)

#define SOCKS5_CMD_CONNECT		(0x01)
#define SOCKS5_CMD_BIND			(0x02)
#define SOCKS5_CMD_UDP_ASSOC	(0x03)
#define SOCKS5_CMD_VALID(cmd) \
	(((cmd) > 0x00) && ((cmd) < 0x04))

#define SOCKS5_ATYPE_IPV4	(0x01)
#define SOCKS5_ATYPE_DOMAIN	(0x03)
#define SOCKS5_ATYPE_IPV6	(0x04)
#define SOCKS5_ATYPE_VALID(cmd) \
	(((cmd) > 0x00) && ((cmd) < 0x05) && ((cmd) != 0x02))

#define SOCKS5_REP_SUCCEEDED			(0x00)
#define SOCKS5_REP_GENERAL_FAILURE		(0x01)
#define SOCKS5_REP_NOT_ALLOWED			(0x02)
#define SOCKS5_REP_NET_UNREACHABLE		(0x03)
#define SOCKS5_REP_HOST_UNREACHABLE		(0x04)
#define SOCKS5_REP_CONN_REFUSED			(0x05)
#define SOCKS5_REP_TTL_EXPIRED			(0x06)
#define SOCKS5_REP_BAD_COMMAND			(0x07)
#define SOCKS5_REP_ATYPE_UNSUPPORTED	(0x08)

/*
 * socks5_conn
 */
typedef struct socks5_conn_t {
	struct bufferevent *client;
	//struct bufferevent *dst;
	enum socks5_conn_status status;
// 	unsigned char auth_method;
// 	unsigned char command;
	char host[256];
	uint16_t port;
	connect_callback cb;
	void *arg;
} socks5_conn;

static void send_auth_methods(socks5_conn *conn)
{
	char data[] = {0x05, 0x01, 0x00}; // version 5 no authentication
	bufferevent_write(conn->client, data, sizeof(data));
	conn->status = SCONN_AUTH_METHODS_SENT;

	bufferevent_enable(conn->client, EV_READ | EV_WRITE);
}

static void send_request(socks5_conn *conn)
{
	char data[7 + 255] = {0x05, 0x01, 0x00}; // version 5 connect
	data[3] = 0x03; // domain
	size_t domain_len = strlen(conn->host);
	assert(domain_len <= 255);
	uint16_t net_port = htons(conn->port);

	data[4] = domain_len;
	memcpy(data + 5, conn->host, domain_len);
	memcpy(data + 5 + domain_len, &net_port, 2);

	bufferevent_write(conn->client, data, 3 + 1 + 1 + domain_len + 2);

	conn->status = SCONN_REQUEST_SENT;
}

static void read_auth_methods(socks5_conn *conn)
{
	char data[2] = {};
	struct evbuffer *buffer;
	size_t have;

	buffer = bufferevent_get_input(conn->client);
	have = evbuffer_get_length(buffer);

	if (have < 2) // 
		goto needmore;

	evbuffer_copyout(buffer, data, 2);

	if (data[0] != 0x05)
	{
		// ERROR protocol version
		goto fail;
	}
	
	if (data[1] != 0x00) // 0xff close socket
	{
		// non supported method
		goto fail;
	}

	evbuffer_drain(buffer, 2);
	send_request(conn);
	return;

fail:
	conn->status = SCONN_ERROR;
	return;

needmore:
	return;
}

static void read_reply(socks5_conn *conn)
{
	uint8_t data[7 + 255] = {};
	struct evbuffer *buffer;
	size_t have, consume = 0;

	buffer = bufferevent_get_input(conn->client);
	have = evbuffer_get_length(buffer);

	if (have < 8) // domain at least 1 byte
		goto needmore;

	evbuffer_copyout(buffer, data, 8);
	if (data[0] != 0x05)
	{
		// ERROR protocol version
		goto fail;
	}

	if (data[1] != 0x00) // fail
	{
		// non supported method
		goto fail;
	}

	uint8_t atype = data[3];
	
	if (atype == SOCKS5_ATYPE_IPV4) {
		if (have < 10)
			goto needmore;

		consume = 10;
	}
	else if (atype == SOCKS5_ATYPE_IPV6) {
		if (have < 22)
			goto needmore;

		consume = 22;
	}
	else if (atype == SOCKS5_ATYPE_DOMAIN) {
		unsigned char addrlen;

		addrlen = data[4];
		if (have < (7 + addrlen))
			goto needmore;

		consume = 7 + addrlen;
	}
	else
	{
		goto fail ; // Unknown address type
	}

ok:
	evbuffer_drain(buffer, consume);
	conn->status = SCONN_CONNECT_TRANSMITTING;
	return;

fail:
	conn->status = SCONN_ERROR;

needmore:
	return;
}

static void readcb(struct bufferevent *bev, void *ctx)
{
	socks5_conn *conn = (socks5_conn*)ctx;

	switch (conn->status)
	{
	case SCONN_AUTH_METHODS_SENT:
		read_auth_methods(conn);
		break;
	case SCONN_REQUEST_SENT:
		read_reply(conn);
		break;
	default:
		break;
	}

	if (conn->status == SCONN_CONNECT_TRANSMITTING)
	{
		bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

		conn->cb(bev, conn->arg);

		free(conn);
	}
	else if (conn->status == SCONN_ERROR)
	{
		// error
		conn->cb(NULL, conn->arg);

		free(conn);
	}
}
static void writecb(struct bufferevent *bev, void *ctx)
{
	socks5_conn *conn = (socks5_conn*)ctx;
	if (conn->status == SCONN_INIT)
	{
		send_auth_methods(conn);
	}
}

static void eventcb(struct bufferevent *bev, short what, void *ctx)
{
	socks5_conn *conn = (socks5_conn*)ctx;
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		fprintf(stderr, "sock %d error\n", bufferevent_getfd(bev));

		// error
		conn->cb(NULL, conn->arg);

		free(conn);
	}
	else if (what & BEV_EVENT_CONNECTED){
		fprintf(stderr, "connected with sock %d\n", bufferevent_getfd(bev));

		if (conn->status == SCONN_INIT)
		{
			/* socks5 */
			writecb(bev, ctx);
		}
		else
		{
			/* TCP */
			bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

			conn->cb(bev, conn->arg);

			free(conn);
		}
	}
}

void connect_cb(struct bufferevent *bev, void *arg)
{
	if (bev)
	{
		fprintf(stderr, "connect success\n");

		const char headers[] = 
			"GET / HTTP/1.1\r\n"
			"Connection: Keep-Alive\r\n"
			"\r\n";
		bufferevent_write(bev, headers, sizeof(headers) - 1); // without ending '\0'
	}
	else
	{
		fprintf(stderr, "connect fail\n");
	}
}

void connect_socks5(struct event_base *evbase, struct evdns_base *evdns_base, const char *hostname, int port, connect_callback cb, void *arg)
{
	struct bufferevent *bev;
	socks5_conn *conn = (socks5_conn*)calloc(1, sizeof(socks5_conn));

	strcpy(conn->host, hostname);
	conn->port = port;
	conn->cb = cb;
	conn->arg = arg;

	if (g_socks_server && g_socks_port != 0)
	{
		hostname = g_socks_server;
		port =g_socks_port;

		conn->status = SCONN_INIT;
	}
	
	bev = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE/*|BEV_OPT_DEFER_CALLBACKS*/);
	if (bev == NULL || bufferevent_socket_connect_hostname(bev, evdns_base, PF_UNSPEC, hostname, port) < 0) {
		goto fail;
	}

	bufferevent_setcb(bev, readcb, writecb, eventcb, conn);
	//bufferevent_enable(bev, EV_WRITE);

	conn->client = bev;
	return;

fail:
	perror("bufferevent_socket_connect");
	bufferevent_free(bev);
	cb(NULL, arg);
	if (conn)
		free(conn);
}

#if 0

const char *g_socks_server = "127.0.0.1";
int g_socks_port = 1080;

int main( int argc, char* argv[] )
{
	struct event *ev_sigterm;
	event_base  *evbase;
	evdns_base *evdns;

#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
#endif

	evbase = event_base_new();
	evdns = evdns_base_new(evbase, 1);
	evdns_base_set_option(evdns, "randomize-case:", "0");

#ifndef WIN32
	ev_sigterm = evsignal_new(evbase, SIGTERM, sigterm_cb, evbase);
	evsignal_add(ev_sigterm, NULL);
#endif

	connect_socks5(evbase, evdns, "www.baidu.com", 80, connect_cb, NULL);

	event_base_loop(evbase, 0);

	printf("Clean exit\n");
	return 0;
}
#endif
