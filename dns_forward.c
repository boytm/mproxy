#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef _WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/util.h>

#include "dns_forward.h"
#include "connector.h"
#include "log.h"
#include "utils.h"
#include "parse_forward_param.h"

#ifdef __GNUC__
# define PACK( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#elif defined(_MSC_VER)
# define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
#endif

#define QID_BUCKET_SIZE 1024
#define MAX_INFIGHT (QID_BUCKET_SIZE * 2)
#define DEFAULT_DNS_SERVER_PORT 53

/* True iff e is an error that means a read/write operation can be retried. */
#ifndef WIN32
# define EVUTIL_ERR_RW_RETRIABLE(e)				\
	((e) == EINTR || (e) == EAGAIN)
#else
# define EVUTIL_ERR_RW_RETRIABLE(e)					\
	((e) == WSAEWOULDBLOCK || (e) == WSAEINTR)
#endif

#undef LIST_FOREACH_SAFE
#define	LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = LIST_FIRST((head));				\
	    (var) && ((tvar) = LIST_NEXT((var), field), 1);		\
	    (var) = (tvar))


typedef struct dns_header_t {
	uint16_t id;
	uint8_t qr_opcode_aa_tc_rd;
	uint8_t ra_z_rcode;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount; // may be >0 for EDNS queries
} dns_header;

PACK(struct dns_tcp_pkt_t {
	uint16_t sz;
	union {
		dns_header hdr;
		char raw[0xffff];
	} dns;
});

typedef struct dns_tcp_pkt_t dns_tcp_pkt;

typedef struct inflight_req_t {
    RB_ENTRY(inflight_req_t) next_rb;
    LIST_ENTRY(inflight_req_t) next;

    uint16_t id;        // in network byte order
    uint16_t mapped_id; // in network byte order

    struct sockaddr_storage clientaddr;
} inflight_req;

LIST_HEAD(qid_head, inflight_req_t);

static int inflight_req_compare(const inflight_req *lhs, const inflight_req *rhs)
{
    if (lhs->id == rhs->id) {
        return evutil_sockaddr_cmp((const struct sockaddr *)(&lhs->clientaddr),
                                   (const struct sockaddr *)(&rhs->clientaddr),
                                   1);
    } else {
        return lhs->id - rhs->id;
    }
}

RB_HEAD(inflight_req_tree, inflight_req_t);
RB_GENERATE(inflight_req_tree, inflight_req_t, next_rb, inflight_req_compare);

typedef struct dns_forwarder_t
{
    int inflight_count;
    uint16_t upstream_ready:1;
    uint16_t dns_server_port;
    char *dns_server;
    
    struct event*    listener;
    struct bufferevent *bev;  // upstream dns server
    struct evdns_base *evdns_base;

    struct inflight_req_tree tree_head;
    struct qid_head queries_by_qid[QID_BUCKET_SIZE];
} dnsu2t_instance;


static inflight_req* request_find_from_trans_id(dnsu2t_instance *instance, uint16_t trans_id) {
    struct qid_head *qhead = &instance->queries_by_qid[trans_id % QID_BUCKET_SIZE];

    inflight_req *item = NULL;

    LIST_FOREACH(item, qhead, next) {
        if (item && item->mapped_id == trans_id) {
            return item;
        }
    }

    return NULL;
}


static uint16_t transaction_id_pick(dnsu2t_instance *instance) {
	for (;;) {
		uint16_t trans_id;
		evutil_secure_rng_get_bytes(&trans_id, sizeof(trans_id));

		if (trans_id == 0xffff) continue;
		/* now check to see if that id is already inflight */
		if (request_find_from_trans_id(instance, trans_id) == NULL)
			return trans_id;
	}
}


static void clear_infight_queries(dnsu2t_instance *self)
{
    int i = 0;
    for (i = 0; i < QID_BUCKET_SIZE; ++i) {
        struct qid_head *qhead = &self->queries_by_qid[i];
            
        inflight_req *item = NULL;
        inflight_req *tvar = NULL;

        LIST_FOREACH_SAFE(item, qhead, next, tvar) {
            inflight_req *ti = RB_REMOVE(inflight_req_tree, &self->tree_head, item);
            assert(ti == item);
            free(item);
            --self->inflight_count;
        }
        LIST_INIT(qhead); // clear list
    }
    assert(self->inflight_count == 0);
}

static void dns_upstream_readcb(struct bufferevent *bev, void *ctx)
{
    dnsu2t_instance *self = ctx;
    for (;;) {
        dns_tcp_pkt in;        
        struct evbuffer *buffer;
        size_t have;
        int sent;
        evutil_socket_t fd = event_get_fd(self->listener);

        buffer = bufferevent_get_input(self->bev);
        have = evbuffer_get_length(buffer);

        if (have < 2) // 
            goto needmore;

        evbuffer_copyout(buffer, &in.sz, sizeof(in.sz));
        uint16_t pktlen = ntohs(in.sz);
        if (pktlen < sizeof(dns_header)) {
            LOGE("malformed DNS reply");
            goto failed;
        }
        if (have < pktlen + sizeof(in.sz)) {
            goto needmore;
        }

        bufferevent_read(bev, &in, pktlen + sizeof(in.sz));
        uint16_t qid = in.dns.hdr.id;
        inflight_req* req = request_find_from_trans_id(self, qid);
        assert(req);
        in.dns.hdr.id = req->id; // restore id
        --self->inflight_count;
        RB_REMOVE(inflight_req_tree, &self->tree_head, req);
        // struct qid_head *qhead = &self->queries_by_qid[qid % QID_BUCKET_SIZE];
        LIST_REMOVE(req, next);
        
        sent = sendto(fd, in.dns.raw, pktlen, 0,
                        (struct sockaddr*)&req->clientaddr, sizeof(req->clientaddr)
        );
        free(req);
        if (sent < 0) {
            int err = evutil_socket_geterror(fd);
            if (EVUTIL_ERR_RW_RETRIABLE(err))
                return;
            LOGE("Error %s (%d) while writing response to port; dropping", evutil_socket_error_to_string(err), err);
        }
    }
    return;

failed:
    self->bev = NULL;
    self->upstream_ready = 0;
    clear_infight_queries(self);
    bufferevent_free(bev);
    return;

needmore:
    return;
}

static void dns_upstream_eventcb(struct bufferevent *bev, short what, void *ctx)
{
    dnsu2t_instance *self = ctx;
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        LOGI("dns upstream bev %p (sock %d) event: 0x%hx", bev, bufferevent_getfd(bev), what);

        // error
        self->bev = NULL;
        self->upstream_ready = 0;
        clear_infight_queries(self);

        bufferevent_free(bev);
    }
}

static void dns_upstream_connect_cb(struct bufferevent *bev, void *arg)
{
    int error;
    dnsu2t_instance *self = arg;
    struct event_base *base = event_get_base(self->listener);
    struct evdns_base *evdns = self->evdns_base;

    if (NULL == bev) {
        LOGE("connect upstream failed, retry");
        connect_upstream(base, evdns, self->dns_server, self->dns_server_port, dns_upstream_connect_cb, self);
        return;
    }
    error = event_add(self->listener, NULL);
    if (error) {
        LOGE("enable dns listener event failed");
        exit(1);
    }
    self->bev = bev;
    self->upstream_ready = 1;
    bufferevent_setcb(bev, dns_upstream_readcb, NULL, dns_upstream_eventcb, self);
    bufferevent_enable(bev, EV_READ);
}

static void dns_read_request(int srvfd, short what, void *arg)
{
    dnsu2t_instance *self = arg;
    struct sockaddr_storage ss;
    ev_socklen_t addrlen = sizeof(ss);
    dns_tcp_pkt in;

    assert(self->listener);
    struct event_base *base = event_get_base(self->listener);
    struct evdns_base *evdns = self->evdns_base;

    assert(srvfd == event_get_fd(self->listener));
    if (! (self->bev && self->upstream_ready)) {
        event_del(self->listener);
        connect_upstream(base, evdns, self->dns_server, self->dns_server_port, dns_upstream_connect_cb, self);
        return;
    }

    for (;;) {
        const int r =
            recvfrom(srvfd, in.dns.raw, sizeof(in.dns.raw), 0, (struct sockaddr *)&ss, &addrlen);
        if (r < 0) {
            int err = evutil_socket_geterror(srvfd);
            if (EVUTIL_ERR_RW_RETRIABLE(err))
                return;
            LOGE("recvfrom failed: %s", evutil_socket_error_to_string(err));
            return;
        }
        if (r < sizeof(dns_header) || r > 65536) {
            LOGE("invalid dns rquest");
            continue;
        }

        inflight_req *key = (inflight_req*)calloc(1, sizeof(inflight_req));
        key->id = in.dns.hdr.id;
        memcpy(&key->clientaddr, &ss, addrlen);

        // find
        inflight_req *req = RB_FIND(inflight_req_tree, &self->tree_head, key);
        if (req) {
            // dns query re-transmission
            continue;
        }

        if (self->inflight_count > MAX_INFIGHT) {
            // too many inflight queries, ignore new queries
            continue;
        }

        uint16_t trans_id = transaction_id_pick(self);

        key->mapped_id = trans_id;
        in.dns.hdr.id = trans_id;
        in.sz = htons(r);
        bufferevent_write(self->bev, &in, r + 2);

        self->inflight_count++;

        // insert into client rb tree
        if (RB_INSERT(inflight_req_tree, &self->tree_head, key)) {
            LOGE("insert into rb tree failed");
            continue;
        }

        // insert into relay list
        struct qid_head *qhead = &self->queries_by_qid[trans_id % QID_BUCKET_SIZE];
        LIST_INSERT_HEAD(qhead, key, next);
    }
}

void dns_forwarder_free(struct dns_forwarder_t *instance)
{
    if (!instance) {
        return;
    }
    if (instance->bev) {
        bufferevent_free(instance->bev);
        instance->bev = NULL;
    }

    if (instance->listener && event_initialized(instance->listener)) {
        if (event_del(instance->listener) != 0)
            LOGE("event_del failed");
        if (evutil_closesocket(event_get_fd(instance->listener)) != 0)
            LOGE("close listener fd failed");
        event_free(instance->listener);
        instance->listener = NULL;
    }

    clear_infight_queries(instance);
    free(instance->dns_server);
    instance->dns_server = NULL;

    memset(instance, 0, sizeof(*instance));
    free(instance);
}

struct dns_forwarder_t* dns_forwarder_new(struct event_base *evbase, struct evdns_base *evdns_base, struct forwarder_param_t *param)
{
    evutil_socket_t fd = -1;
    int             on = 1;
    int             error;
    int             i;
    char            bindaddr[INET6_ADDRSTRLEN + 6] = {0};
    dnsu2t_instance *instance = calloc(1, sizeof(dnsu2t_instance));
    instance->evdns_base = evdns_base;
    instance->dns_server = strdup(param->forward_ip);
    instance->dns_server_port = param->forward_port;
    snprintf(bindaddr, sizeof(bindaddr) - 1, "%s:%hu", param->bind_ip, param->bind_port);

    // initialize RB_TREE and LIST
    for (i = 0; i < QID_BUCKET_SIZE; ++i){
        struct qid_head *qhead = &instance->queries_by_qid[i];
        LIST_INIT(qhead); // clean list
    }

    RB_INIT(&instance->tree_head);

    // create listen socket
    struct sockaddr_storage ss;
    struct sockaddr *address;
    int addrlen = sizeof(ss);
    if (evutil_parse_sockaddr_port(bindaddr, (struct sockaddr *)&ss, &addrlen)) {
        LOGE("Unable to parse address %s", bindaddr);
        goto failed;
    }
    address = (struct sockaddr*)&ss;

    fd = socket(address->sa_family, SOCK_DGRAM, 0);
    if (fd == -1) {
        goto failed;
    }

    evutil_make_socket_closeonexec(fd);
    evutil_make_socket_nonblocking(fd);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));

    if (bind(fd, address, addrlen)) {
        LOGE("bind address failed");
        goto failed;
    }

    instance->listener = event_new(evbase, fd, EV_READ | EV_PERSIST, dns_read_request, instance);
    if (!instance->listener) {
        goto failed;
    }
    fd = -1; // transfer ownership
    error = event_add(instance->listener, NULL);
    if (error) {
        goto failed;
    }

    LOGI("DNS forwarding listen at %s, forward to %s:%hu", bindaddr, instance->dns_server, instance->dns_server_port);
    return instance;

failed:
    if (fd != -1) {
        evutil_closesocket(fd);
    }
    dns_forwarder_free(instance);
    return NULL;
}
