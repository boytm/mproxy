#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>
#include <evhtp.h>
#include <event2/dns.h>

static void 
print_error(evhtp_request_t * req, evhtp_error_flags errtype, void * arg) {
	printf("evhtp error\n");
}


static void
request_cb(evhtp_request_t * req, void * arg) {
    printf("hi %zu\n", evbuffer_get_length(req->buffer_in));
}

static evhtp_res
print_data(evhtp_request_t * req, evbuf_t * buf, void * arg) {
size_t len = evbuffer_get_length(buf);

    printf("Got %zu bytes\n", len);
fwrite(evbuffer_pullup(buf, len), 1, len, stdout);
    printf("-------\n");

    return EVHTP_RES_OK;
}

static evhtp_res
print_new_chunk_len(evhtp_request_t * req, uint64_t len, void * arg) {
    printf("started new chunk, %" PRIu64 "  bytes\n", len);

    return EVHTP_RES_OK;
}

static evhtp_res
print_chunk_complete(evhtp_request_t * req, void * arg) {
    printf("ended a single chunk\n");

    return EVHTP_RES_OK;
}

static evhtp_res
print_chunks_complete(evhtp_request_t * req, void * arg) {
    printf("all chunks read\n");

    return EVHTP_RES_OK;
}
static evhtp_res print_headers(evhtp_request_t * req, evhtp_headers_t * hdr, void * arg) {
    printf("all headers ok\n");
    evhtp_kv_t * kv;

    TAILQ_FOREACH(kv, hdr, next) {
        printf("%*s:%s\n", kv->klen, kv->key, kv->val);
    }


    return EVHTP_RES_OK;
}

static evhtp_res print_conn_error(evhtp_connection_t * connection, evhtp_error_flags errtype, void * arg) {
    printf("connection hook error \n");

    return EVHTP_RES_OK;
}



int
main(int argc, char ** argv) {
    evbase_t           * evbase;
    struct evdns_base  * evdns;
    evhtp_connection_t * conn;
    evhtp_request_t    * request;
    const char *path = "/";
    const char *host = argv[1];
    if (argc >= 3) 
	    path = argv[2];

    evbase  = event_base_new();
    evdns = evdns_base_new(evbase, 1);
    conn    = evhtp_connection_new_dns(evbase, evdns, host, 80);
    request = evhtp_request_new(request_cb, evbase);

    evhtp_set_hook(&request->hooks, evhtp_hook_on_error, print_error, NULL);
    evhtp_set_hook(&request->hooks, evhtp_hook_on_headers, print_headers, evbase);
    evhtp_set_hook(&request->hooks, evhtp_hook_on_read, print_data, evbase);
    evhtp_set_hook(&request->hooks, evhtp_hook_on_new_chunk, print_new_chunk_len, NULL);
    evhtp_set_hook(&request->hooks, evhtp_hook_on_chunk_complete, print_chunk_complete, NULL);
    evhtp_set_hook(&request->hooks, evhtp_hook_on_chunks_complete, print_chunks_complete, NULL);

    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("Host", host, 0, 0));
    //evhtp_headers_add_header(request->headers_out,
    //                         evhtp_header_new("Accept-Encoding", "deflate, gzip", 0, 0));
    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("User-Agent", "libevhtp", 0, 0));
    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("Connection", "close", 0, 0));
    evhtp_headers_add_header(request->headers_out,
                             evhtp_header_new("Accept", "*/*", 0, 0));

    evhtp_set_hook(&conn->hooks, evhtp_hook_on_conn_error, print_conn_error, NULL);

    evhtp_make_request(conn, request, htp_method_GET, path);
    //evhtp_make_request(conn, request, htp_method_HEAD, "/");

    event_base_loop(evbase, 0);
    event_base_free(evbase);

    return 0;
}

