#pragma once
#include <stdint.h>
#include <event2/dns.h>

struct forwarder_param_t;

struct dns_forwarder_t;
struct dns_forwarder_t* dns_forwarder_new(struct event_base *evbase, struct evdns_base *evdns_base, struct forwarder_param_t *param);
void dns_forwarder_free(struct dns_forwarder_t*);
