#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include "libevhtp/htparse.h"

#include "connector.h"


enum http_conn_status {
	HTTP_CONN_TCP_INIT = 0,
	HTTP_CONN_INIT = 100,  /* HTTP CONNECT method */
	HTTP_CONN_REQUEST_SENT,
	HTTP_CONN_CONNECT_TRANSMITTING,
	HTTP_CONN_ERROR
};

/*
 * http_conn
 */
typedef struct http_conn_t {
	struct bufferevent *client;
	//struct bufferevent *dst;
	enum http_conn_status status;

	char host[256];
	uint16_t port;
	uint8_t response_complete;
	htparser *parser;
	connect_callback cb;
	void *arg;
} http_conn;

static void free_http_conn(http_conn *conn)
{
	/* ignore bufferevent which will be returned */
	if (conn->parser) {
		free(conn->parser);
		conn->parser = NULL;
	}
	free(conn);
}

static void send_request(http_conn *conn)
{
	char data[1024] = {'\0'};
	size_t data_len = sizeof(data) - 1;
	int ret = snprintf(data, data_len,
		"CONNECT %s:%d HTTP/1.1\r\n"
		"Host: %s:%d\r\n"
		"Proxy-Connection: Keep-Alive\r\n"
		"\r\n", conn->host, conn->port, conn->host, conn->port);
	if (ret == -1 || ret >= data_len) {
		LOGE("format HTTP request failed");
		goto fail;
	}

	bufferevent_write(conn->client, data, ret);
	bufferevent_enable(conn->client, EV_READ | EV_WRITE);

	conn->status = HTTP_CONN_REQUEST_SENT;
	return;

fail:
	conn->status = HTTP_CONN_ERROR;
}

static int _hdrs_complete(htparser * p) {
    http_conn * conn = (http_conn *)htparser_get_userdata(p);

    conn->response_complete = 1;

	/* 0 need body, 1 no body */
    return 1;
}

static htparse_hooks hooks = {
    .on_hdrs_complete    = _hdrs_complete
};

static void read_response(http_conn *conn)
{
	struct evbuffer *buffer;
	size_t have;
	size_t parsed_sz;
	htparser *p = conn->parser;

	buffer = bufferevent_get_input(conn->client);
	have = evbuffer_get_length(buffer);
	char *data = (char *)evbuffer_pullup(buffer, have);

	/* TODO: response have body */
    parsed_sz = htparser_run(p, &hooks, data, have);

	evbuffer_drain(buffer, parsed_sz);
	if (htparser_get_error(p) != htparse_error_none) {
		LOGE("parse HTTP response failed: %s", htparser_get_strerror(p));
		goto fail;
	}

	if (conn->response_complete) {
		unsigned int status = htparser_get_status(p);
		if (status >= 200 && status < 300) {
			assert(parsed_sz == have);
			conn->status = HTTP_CONN_CONNECT_TRANSMITTING;
		} else {
			LOGE("HTTP response status: %d", status);
			goto fail;
		}
	}
	return;

fail:
	conn->status = HTTP_CONN_ERROR;
	return;
}

static void readcb(struct bufferevent *bev, void *ctx)
{
	http_conn *conn = (http_conn*)ctx;

	switch (conn->status)
	{
	case HTTP_CONN_REQUEST_SENT:
		read_response(conn);
		break;
	default:
		break;
	}
	LOGD("connection status: %d", conn->status);

	if (conn->status == HTTP_CONN_CONNECT_TRANSMITTING)	{
        LOGD("HTTP negotiate successfully");
		bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

		conn->cb(bev, conn->arg);

		free_http_conn(conn);
	} else if (conn->status == HTTP_CONN_ERROR)	{
        LOGE("HTTP negotiate ERROR");
		// error
		conn->cb(NULL, conn->arg);

		free_http_conn(conn);
        bufferevent_free(bev); // protocol error, close socket
	}
}

static void eventcb(struct bufferevent *bev, short what, void *ctx)
{
	http_conn *conn = (http_conn*)ctx;
	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        char buf[4096] = {'\0'};
		// during handshake, EOF is an error also
		LOGE("bev %p (sock %d) event: 0x%hx %s", bev, bufferevent_getfd(bev), what, socket_error(buf, sizeof(buf)));

		goto fail;
	} else if (what & BEV_EVENT_CONNECTED) {
		LOGD("upstrem connected with bev %p (sock %d)", bev, bufferevent_getfd(bev));
#if defined TCP_NODELAY
		if (g_enable_nodelay == 1) {
			int on = 1;
			setsockopt(bufferevent_getfd(bev), IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on));
    	}
#endif

		if (conn->status == HTTP_CONN_INIT) {
			/* HTTP */
			send_request(conn);
			
			if (conn->status == HTTP_CONN_ERROR) {
				goto fail;
			}
		} else {
			/* TCP */
			bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

			conn->cb(bev, conn->arg);

			free_http_conn(conn);
		}
	}
	return;

fail:
	// error
	conn->cb(NULL, conn->arg);

	free_http_conn(conn);
	bufferevent_free(bev);
}

void connect_http(struct event_base *evbase, struct evdns_base *evdns_base, const char *hostname, int port, connect_callback cb, void *arg)
{
	struct bufferevent *bev = NULL;
	http_conn *conn = (http_conn*)calloc(1, sizeof(http_conn));
    if (NULL == conn) {
        goto fail;
    }

	strcpy(conn->host, hostname);
	conn->port = port;
	conn->cb = cb;
	conn->arg = arg;

	if (hostname && port) {
		/* tunnel via HTTP CONNECT method */
		htparser * p = htparser_new();
		if (p == NULL) {
			goto fail;
		}
		htparser_init(p, htp_type_response);
		htparser_set_userdata(p, conn);
		conn->parser = p;

		conn->status = HTTP_CONN_INIT;
	} /* else: just a connection to HTTP proxy */
	
	hostname = g_socks_server;
	port =g_socks_port;
	
	bev = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE/*|BEV_OPT_DEFER_CALLBACKS*/);
	if (NULL == bev) {
        LOGE("bufferevent create failed");
		goto fail;
	}

	// eventcb() might be called in bufferevent_socket_connect_hostname(), when name resolve is done 
	// immediately and bufferevent_socket_connect() failed immediately.
	// When hostname is pure IP address, or hostname is in /etc/hosts file, evutil_getaddrinfo_async() call its 
	// callback in itself, not after.
	// bufferevent_socket_connect() usually failed immediately with socket() exceed ulimit open files.
	conn->client = bev;
	bufferevent_setcb(bev, readcb, NULL, eventcb, conn); /* must be set before bufferevent_socket_connect_hostname() */

	if (bufferevent_socket_connect_hostname(bev, evdns_base, PF_UNSPEC, hostname, port) < 0) {
        LOGE("bufferevent connect %s:%d failed", hostname, port);
		goto fail;
	}

	// Because eventcb() might have been called, so we cannot do anything with bev or conn here.
	// If you want, you must use BEV_OPT_DEFER_CALLBACKS to force eventcb() executed after bufferevent_socket_connect_hostname().

	return;

fail:
	if (bev)
		bufferevent_free(bev);
	cb(NULL, arg);
	if (conn)
		free_http_conn(conn);
}

#if 0

void connect_cb(struct bufferevent *bev, void *arg)
{
	if (bev) {
		fprintf(stderr, "connect success\n");

		const char headers[] = 
			"GET / HTTP/1.1\r\n"
			"Connection: Keep-Alive\r\n"
			"\r\n";
		bufferevent_write(bev, headers, sizeof(headers) - 1); // without ending '\0'
	} else {
		fprintf(stderr, "connect fail\n");
	}
}

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

	connect_http(evbase, evdns, "www.baidu.com", 80, connect_cb, NULL);

	event_base_loop(evbase, 0);

	printf("Clean exit\n");
	return 0;
}
#endif
