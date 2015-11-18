#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include "evhtp.h"
#include <event2/dns.h>


void relay(struct bufferevent *b_in, struct evdns_base *evdns_base, const char *hostname, int port);
#ifdef USE_THREAD
static struct evdns_base  * evdnss[128] = {};
#else
static struct evdns_base* evdns = NULL;
#endif

static void 
print_error(evhtp_request_t * req, evhtp_error_flags errtype, void * arg) {
	printf("evhtp error\n");
}

int
make_request(evbase_t         * evbase,
	     struct evdns_base* evdns,
             evthr_t          * evthr,
             const char * const host,
             const short        port,
             const char * const path,
	     htp_method 	method,
             evhtp_headers_t  * headers,
             evbuf_t    * 		body,
             evhtp_callback_cb  cb,
             void             * arg) {
    evhtp_connection_t * conn;
    evhtp_request_t    * request;
evhtp_header_t *header = NULL;

    conn         = evhtp_connection_new_dns(evbase, evdns, host, port);
    conn->thread = evthr;
    request      = evhtp_request_new(cb, arg);

    evhtp_set_hook(&request->hooks, evhtp_hook_on_error, print_error, NULL);

    evhtp_headers_add_headers(request->headers_out, headers);
    if((header = evhtp_kvs_find_kv(request->headers_out, "Connection"))) {
	    evhtp_header_rm_and_free(request->headers_out, header);
    }
    if((header = evhtp_kvs_find_kv(request->headers_out, "Proxy-Connection"))) {
	    evhtp_header_rm_and_free(request->headers_out, header);
    }
    //if((header = evhtp_kvs_find_kv(request->headers_out, "Accept-Encoding"))) {
	//    evhtp_header_rm_and_free(request->headers_out, header);
    //}
    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("Connection", "close", 0, 0));


    evbuffer_prepend_buffer(request->buffer_out, body);

    printf("Making backend request...\n");
    evhtp_make_request(conn, request, method, path);
    printf("async.\n");

    return 0;
}

static void
backend_cb(evhtp_request_t * backend_req, void * arg) {
	evhtp_header_t *header = NULL;
    evhtp_request_t * frontend_req = (evhtp_request_t *)arg;

    evbuffer_prepend_buffer(frontend_req->buffer_out, backend_req->buffer_in);
    evhtp_headers_add_headers(frontend_req->headers_out, backend_req->headers_in);

	// Content-Length will be auto set by libevhtp
    if((header = evhtp_kvs_find_kv(frontend_req->headers_out, "Transfer-Encoding"))) {
	    evhtp_header_rm_and_free(frontend_req->headers_out, header);
    }
    if((header = evhtp_kvs_find_kv(frontend_req->headers_out, "Connection"))) {
	    evhtp_header_rm_and_free(frontend_req->headers_out, header);
    }

    /*
     * char body[1024] = { '\0' };
     * ev_ssize_t len = evbuffer_copyout(frontend_req->buffer_out, body, sizeof(body));
     * printf("Backend %zu: %s\n", len, body);
     */

    printf("backend http response.\n");
    //evhtp_send_reply(frontend_req, EVHTP_RES_OK);
    evhtp_send_reply(frontend_req, evhtp_request_status(backend_req));
    evhtp_request_resume(frontend_req);

    //evhtp_connection_t * conn = backend_req->conn;
    //evhtp_request_free(backend_req);
    //evhtp_connection_free(conn);
}

static void
frontend_cb(evhtp_request_t * req, void * arg) {
#ifdef USE_THREAD
    int * aux;
    int   thr;
	struct evdns_base  * evdns;

    aux = (int *)evthr_get_aux(req->conn->thread);
    thr = *aux;

    printf("  Received frontend request on thread %d... ", thr);
	evdns = evdnss[thr];
    evbase_t    * evbase  = evthr_get_base(req->conn->thread);
#else
	evbase_t    * evbase  = req->conn->evbase;
#endif

    const char *host = req->uri->authority->hostname; 
    uint16_t port = req->uri->authority->port ?  req->uri->authority->port : 80;
    printf("Ok. %s:%u\n", host, port);

    /* Pause the frontend request while we run the backend requests. */
    evhtp_request_pause(req);

    if (htp_method_CONNECT == req->method) {
	    evhtp_headers_add_header(req->headers_out,
			    evhtp_header_new("Connection", "Keep-Alive", 0, 0));
	    evhtp_headers_add_header(req->headers_out,
			    evhtp_header_new("Content-Length", "0", 0, 0));
	    evhtp_send_reply(req, EVHTP_RES_OK);

	    printf("relay http socket.\n");
	    evbev_t * bev = evhtp_request_take_ownership(req);
	    relay(bev, evdns, host, port);
    } else {
		evbuf_t *uri = evbuffer_new();
		if (req->uri->query_raw) {
			evbuffer_add_printf(uri, "%s?%s", req->uri->path->full, req->uri->query_raw);
		} else {
			evbuffer_add_reference(uri, req->uri->path->full, strlen(req->uri->path->full), NULL, NULL);
		}

	    make_request(evbase,
			    evdns,
			    req->conn->thread,
			    //"127.0.0.1", 80,
			    host, port,
			    (char*)evbuffer_pullup(uri, -1),
			    req->method,
			    req->headers_in, req->buffer_in, 
				backend_cb, req);

		evbuffer_free(uri);
    }
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

    printf("Spinning up a thread: %d\n", ++aux);
    evthr_set_aux(thr, &aux);
    evbase_t     * evbase = evthr_get_base(thr);
    evdnss[aux] = evdns_base_new(evbase, 1);
}
#endif

int
main(int argc, char ** argv) {
    struct event *ev_sigterm;
    evbase_t    * evbase  = event_base_new();
    evhtp_t     * evhtp   = evhtp_new(evbase, NULL);

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
    evhtp_set_gencb(evhtp, frontend_cb, NULL);
#endif

#ifndef WIN32
    ev_sigterm = evsignal_new(evbase, SIGTERM, sigterm_cb, evbase);
    evsignal_add(ev_sigterm, NULL);
#endif
    evhtp_bind_socket(evhtp, "0.0.0.0", 8081, 1024);
    event_base_loop(evbase, 0);

    printf("Clean exit\n");
    return 0;
}

