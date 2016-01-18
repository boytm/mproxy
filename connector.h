#pragma once
#include "utils.h"

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

