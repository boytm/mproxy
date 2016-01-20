#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include "evhtp.h"
#include <event2/dns.h>

#include "connector.h"

#define MAX_OUTPUT (512*1024)

void relay(struct bufferevent *b_in, struct bufferevent *b_out);

static void	backend_cb(evhtp_request_t * backend_req, void * arg);
static void connect_cb(struct bufferevent *bev, void *arg);
static void lru_get_cb(evhtp_connection_t *conn, void *arg);

#ifdef USE_THREAD
static struct evdns_base  * evdnss[128] = {};
#else
struct evdns_base* evdns = NULL;
#endif
const char *g_socks_server = NULL;
int g_socks_port = 1080;
int use_syslog = 0;

enum upstream_mode {
	UPSTREAM_TCP,
	UPSTREAM_SOCKS5,
	UPSTREAM_SS,
};
enum upstream_mode g_upstream_mode = UPSTREAM_TCP; // 0. TCP 1. SOCKS5 2. shadowsocks

void connect_upstream(struct event_base *evbase, struct evdns_base *evdns_base, const char *hostname, int port, connect_callback cb, void *arg)
{
	if (strlen(hostname) > 255) {
		LOGE("domain too long");
		return cb(NULL, arg);
	}

#ifdef ENABLE_SS
	if (g_upstream_mode == UPSTREAM_SS)	{
		connect_ss(evbase, evdns_base, hostname, port, cb, arg);
	} else {
#endif
		connect_socks5(evbase, evdns_base, hostname, port, cb, arg);
#ifdef ENABLE_SS
	}
#endif
}

// error occur before read all headers 
static void 
backend_conn_error(evhtp_request_t * req, evhtp_error_flags errtype, void * arg) 
{
	evhtp_request_t * frontend_req = (evhtp_request_t *)arg;
	evhtp_request_t * backend_req = req;
	LOGE("evhtp backend connect error");

	evhtp_send_reply(frontend_req, 502); // return 502 bad gateway, when connect fail
	evhtp_request_resume(frontend_req);

	evhtp_unset_hook(&frontend_req->hooks, evhtp_hook_on_error);
}

// error after read all headers 
static void 
backend_trans_error(evhtp_request_t * req, evhtp_error_flags errtype, void * arg) 
{
	evhtp_request_t * frontend_req = (evhtp_request_t *)arg;
	evhtp_request_t * backend_req = req;
	LOGE("evhtp backend transport error");

	backend_cb(backend_req, frontend_req); // finish transport
}

static void 
frontend_error(evhtp_request_t * req, evhtp_error_flags errtype, void * arg) 
{
	evhtp_request_t * backend_req = (evhtp_request_t *)arg;
	LOGE("evhtp frontend error");

	// cancel request
	evhtp_request_pause(backend_req);
	evhtp_unset_hook(&backend_req->hooks, evhtp_hook_on_error);
	evhtp_connection_t *ev_conn = evhtp_request_get_connection(backend_req);
	evhtp_connection_free(ev_conn);
}

static evhtp_res resume_backend_request(evhtp_connection_t * conn, void * arg) 
{
	evhtp_request_t * backend_req = (evhtp_request_t *)arg;

	LOGD("resume backend request");
	evhtp_request_resume(backend_req); // bug, client can't evhtp_request_resume

	evhtp_unset_hook(&conn->hooks, evhtp_hook_on_write);
	
	return EVHTP_RES_OK;
}


static evhtp_res
backend_body(evhtp_request_t * req, evbuf_t * buf, void * arg) 
{
	evhtp_request_t * frontend_req = (evhtp_request_t *)arg;
	size_t len = evbuffer_get_length(buf);

	//LOGD("relay http body, got %u bytes", (unsigned)len);
	//fwrite(evbuffer_pullup(buf, len), 1, len, stdout);

	evhtp_send_reply_chunk(frontend_req, buf);
	
	evbuffer_drain(buf, -1); // remove readed data

// 	if(evbuffer_get_length(bufferevent_get_output(evhtp_request_get_bev(frontend_req))) > MAX_OUTPUT) {
// 		printf("too many data, stop backend request\n");
// 		evhtp_request_pause(req);
// 
// 		evhtp_set_hook(&evhtp_request_get_connection(frontend_req)->hooks, evhtp_hook_on_write, resume_backend_request, req);
// 	}

	return EVHTP_RES_OK;
}

static evhtp_res backend_headers(evhtp_request_t * backend_req, evhtp_headers_t * headers, void * arg)
{
	evhtp_request_t * frontend_req = (evhtp_request_t *)arg;
	evhtp_header_t *kv = NULL;

    LOGD("all headers ok");

	TAILQ_FOREACH(kv, headers, next) {
		//printf("%*s:%s\n", kv->klen, kv->key, kv->val);
		if (strcasecmp(kv->key, "Connection") == 0)	{
			continue;
		}
		evhtp_kvs_add_kv(frontend_req->headers_out, evhtp_kv_new(kv->key,
			kv->val,
			kv->k_heaped,
			kv->v_heaped));
	}

    evhtp_send_reply_chunk_start(frontend_req, evhtp_request_status(backend_req));
    evhtp_request_resume(frontend_req);

	evhtp_set_hook(&backend_req->hooks, evhtp_hook_on_error, backend_trans_error, frontend_req);

    return EVHTP_RES_OK;
}

int
make_request(evhtp_connection_t * conn,
             evthr_t          * evthr,
             const char * const path,
             htp_method 	method,
             evhtp_headers_t  * headers,
             evbuf_t    * 		body,
             evhtp_callback_cb  cb,
             void             * arg) 
{
    evhtp_request_t    * request;
	evhtp_header_t *kv = NULL;
    evhtp_request_t * frontend_req = (evhtp_request_t *)arg;

#ifndef EVHTP_DISABLE_EVTHR
    conn->thread = evthr;
#endif
    request      = evhtp_request_new(cb, arg);

	TAILQ_FOREACH(kv, headers, next) {
		if (strcasecmp(kv->key, "Connection") == 0) {
			continue;
		}
		if (strcasecmp(kv->key, "Proxy-Connection") == 0) {
			continue;
		}
		evhtp_kvs_add_kv(request->headers_out, evhtp_kv_new(kv->key,
			kv->val,
			kv->k_heaped,
			kv->v_heaped));
	}
    //if((header = evhtp_kvs_find_kv(request->headers_out, "Accept-Encoding"))) {
	//    evhtp_header_rm_and_free(request->headers_out, header);
    //}
//     evhtp_headers_add_header(request->headers_out,
//                              evhtp_header_new("Connection", "close", 0, 0));


    evbuffer_prepend_buffer(request->buffer_out, body);

	// hook
    evhtp_set_hook(&request->hooks, evhtp_hook_on_error, backend_conn_error, arg);
    evhtp_set_hook(&request->hooks, evhtp_hook_on_headers, backend_headers, arg);
    evhtp_set_hook(&request->hooks, evhtp_hook_on_read, backend_body, arg);

    evhtp_set_hook(&frontend_req->hooks, evhtp_hook_on_error, frontend_error, request);

    LOGD("Making backend request...");
    evhtp_make_request(conn, request, method, path);

    return 0;
}

static void
backend_cb(evhtp_request_t * backend_req, void * arg) {
	//evhtp_header_t *header = NULL;
    evhtp_request_t * frontend_req = (evhtp_request_t *)arg;

    LOGD("finish http response.");
    evhtp_send_reply_chunk_end(frontend_req);

    evhtp_unset_hook(&frontend_req->hooks, evhtp_hook_on_error);
	evhtp_unset_hook(&backend_req->hooks, evhtp_hook_on_error);

	if (backend_req->keepalive) {
		const char *host = frontend_req->uri->authority->hostname; 
		uint16_t port = frontend_req->uri->authority->port ? frontend_req->uri->authority->port : 80;
		lru_set(host, port, backend_req->conn);
	}
}

static void
frontend_cb(evhtp_request_t * req, void * arg) {
#ifdef USE_THREAD
    int * aux;
    int   thr;
	struct evdns_base  * evdns;

    aux = (int *)evthr_get_aux(req->conn->thread);
    thr = *aux;

    LOGD("  Received frontend request on thread %d... ", thr);
	evdns = evdnss[thr];
    evbase_t    * evbase  = evthr_get_base(req->conn->thread);
#else
	evbase_t    * evbase  = req->conn->evbase;
#endif

    const char *host = req->uri->authority->hostname; 
    uint16_t port = req->uri->authority->port ? req->uri->authority->port : 80;
    LOGD("http request for %s:%u", host, port);

    /* Pause the frontend request while we run the backend requests. */
    evhtp_request_pause(req);

	if (htp_method_CONNECT == req->method) {
		connect_upstream(evbase, evdns, host, port, connect_cb, req); // async connect
	} else {
		lru_get(host, port, lru_get_cb, req);
	}
}

void connect_cb(struct bufferevent *bev, void *arg)
{
	evhtp_request_t * req = (evhtp_request_t *)arg;

	if (NULL == bev)
	{
		evhtp_send_reply(req, 502); // return 502 bad gateway, when connect fail
		evhtp_request_resume(req);
		return;
	}

	    LOGD("relay http socket.");
	    evbev_t * b_in = evhtp_request_take_ownership(req);

		const char headers[] = 
			"HTTP/1.1 200 OK\r\n"
			"Connection: Keep-Alive\r\n"
			"\r\n";
		bufferevent_write(b_in, headers, sizeof(headers) - 1); // without ending '\0'

	    relay(b_in, bev);
    
}

void lru_get_cb(evhtp_connection_t *conn, void *arg)
{
	evhtp_request_t * req = (evhtp_request_t *)arg;

	if (NULL == conn)
	{
		evhtp_send_reply(req, 502); // return 502 bad gateway, when connect fail
		evhtp_request_resume(req);
		return;
	}

	evbuf_t *uri = evbuffer_new();
	if (req->uri->query_raw) {
		evbuffer_add_printf(uri, "%s?%s", req->uri->path->full, req->uri->query_raw);
	} else {
		evbuffer_add_reference(uri, req->uri->path->full, strlen(req->uri->path->full), NULL, NULL);
	}

	make_request(conn,
#ifndef EVHTP_DISABLE_EVTHR
		req->conn->thread,
#else
		NULL,
#endif
		(char*)evbuffer_pullup(uri, -1),
		req->method,
		req->headers_in, req->buffer_in, 
		backend_cb, req);

	evbuffer_free(uri);
}

/* Terminate gracefully on SIGTERM */
void
sigterm_cb(int fd, short event, void * arg) {
    evbase_t     * evbase = (evbase_t *)arg;
    struct timeval tv     = { .tv_usec = 100000, .tv_sec = 0 }; /* 100 ms */

    event_base_loopexit(evbase, &tv);
}

#ifdef USE_THREAD
void
init_thread_cb(evhtp_t * htp, evthr_t * thr, void * arg) {
    static int aux = 0;

    LOGD("Spinning up a thread: %d", ++aux);
    evthr_set_aux(thr, &aux);
    evbase_t     * evbase = evthr_get_base(thr);
    evdnss[aux] = evdns_base_new(evbase, 1);
	evdns_base_set_option(evdnss[aux], "randomize-case:", "0");
}
#endif

void usage(const char *program)
{
	printf("\nUsage: %s [options]\n", program);
	printf(
        "  -l <local_port>       proxy listen port, default 8081\n"
        "  -b <local_address>    local address to bind, default 0.0.0.0\n"
        "  -p <server_port>      socks5/ss server port\n"
        "  -s <server_address>   socks5/ss server address\n"
        "  -m <encrypt_method>   encrypt method of remote ss server\n"
        "  -k <password>         password of remote ss server\n"
        "  -h                    show help\n");

}

int
main(int argc, char ** argv) {
    struct event *ev_sigterm;
    evbase_t    * evbase = NULL;
    evhtp_t     * evhtp = NULL;
	int			  port = 8081; // default listen port
	const char *bind_address = "0.0.0.0";
	const char *password = NULL;
	const char *method = NULL;
	int opt;

#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
#endif

	while ((opt = getopt(argc, argv, "hu:b:l:p:s:m:k:")) != -1) 
	{
		switch (opt) 
		{
		case 's':
			g_socks_server = optarg;
			break;
		case 'p':
			g_socks_port = atoi(optarg);
			break;
		case 'm':
			method = optarg;
			break;
		case 'k':
			password = optarg;
			break;
		case 'b':
			bind_address = optarg;
			break;
		case 'l':
			port = atoi(optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
			break;
		}
	}

#ifdef ENABLE_SS
	if (password && method)
	{
		g_upstream_mode = UPSTREAM_SS;
		g_ss_method = enc_init(password, method);
		g_ss_server = g_socks_server;
		g_ss_port = g_socks_port;
	}
#endif

	evbase  = event_base_new();
	evhtp   = evhtp_new(evbase, NULL);

#ifdef USE_THREAD
    evhtp_set_gencb(evhtp, frontend_cb, NULL);

#if 0
#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_cfg_t scfg1 = { 0 };

    scfg1.pemfile  = "./server.pem";
    scfg1.privfile = "./server.pem";

    evhtp_ssl_init(evhtp, &scfg1);
#endif
#endif

    evhtp_use_threads(evhtp, init_thread_cb, 2, NULL);
#else
    evdns = evdns_base_new(evbase, 1);
	evdns_base_set_option(evdns, "randomize-case:", "0");
    evhtp_set_gencb(evhtp, frontend_cb, NULL);
#endif

	lru_init(evbase);

#ifndef WIN32
    ev_sigterm = evsignal_new(evbase, SIGTERM, sigterm_cb, evbase);
    evsignal_add(ev_sigterm, NULL);
#endif
    if (0 == evhtp_bind_socket(evhtp, bind_address, port, 1024)) {
		event_base_loop(evbase, 0);
	} else {
		LOGE("Bind address %s failed", bind_address);
	}


    LOGD("Clean exit");
    return 0;
}

