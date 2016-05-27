#pragma once
#include <stdint.h>
#include <event2/dns.h>
#include "evhtp.h"
#include "utils.h"

extern struct evdns_base *evdns;

typedef void (*connect_callback)(struct bufferevent *bev, void *arg);
void connect_upstream(struct event_base *evbase, struct evdns_base *evdns_base, const char *hostname, int port, connect_callback cb, void *arg);

/* shadowsocks */
void connect_ss(struct event_base *evbase, struct evdns_base *evdns_base, const char *hostname, int port, connect_callback cb, void *arg);

/* shadowsocks */
extern int g_ss_method;
extern const char *g_ss_server;
extern int g_ss_port;
extern char *g_ss_key;

/* TCP or SOCKS5 */
void connect_socks5(struct event_base *evbase, struct evdns_base *evdns_base, const char *hostname, int port, connect_callback cb, void *arg);

/* SOCKS5 */
extern const char *g_socks_server;
extern int g_socks_port;

/* lru */
typedef void (*lru_get_callback)(evhtp_connection_t *conn, void *arg);

void lru_set(const char *host, uint16_t port, evhtp_connection_t *conn);
void lru_get(const char *host, uint16_t port, lru_get_callback cb, void *arg);
void lru_init(evbase_t *base);
void lru_fini();


