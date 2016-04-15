#include <assert.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <event2/bufferevent.h>

#include "evhtp.h"
#include "connector.h"

#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif
#define container_of(ptr, type, member) ({ \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define LRU_LIFE 30

static evhtp_res lru_conn_error(evhtp_connection_t *connection, evhtp_error_flags errtype, void *arg);

struct tree_item;

struct connection_item
{
	evhtp_connection_t *connection;
	time_t last_use;
	struct tree_item *parent;

	TAILQ_ENTRY(connection_item) queue_field;
	TAILQ_ENTRY(connection_item) tree_list_field;
};

struct tree_item 
{
	char hostname[256];
	int port;

	TAILQ_HEAD(bev, connection_item) free_list;

	RB_ENTRY(tree_item) field;
};

static TAILQ_HEAD(queue, connection_item) queue = TAILQ_HEAD_INITIALIZER(queue);

static int TreeItemCompare(const struct tree_item *lhs, const struct tree_item *rhs)
{
	if (lhs->port == rhs->port) {
		return strcasecmp(lhs->hostname, rhs->hostname);
	} else {
		return lhs->port - rhs->port;
	}
}

static RB_HEAD(lru, tree_item) lru_head = RB_INITIALIZER(lru_head);
RB_GENERATE(lru, tree_item, field, TreeItemCompare);
struct event *timer_ev = NULL;

evhtp_connection_t * cache_get(const char *hostname, int port)
{
	evhtp_connection_t *retval = NULL;
	struct tree_item *ti = NULL;

	struct tree_item item;
	strcpy(item.hostname, hostname);
	item.port = port;

	ti = RB_FIND(lru, &lru_head, &item);
	if (ti) {
		struct connection_item *bi = TAILQ_FIRST(&ti->free_list);
		if (bi) {
			assert(bi->parent == ti);
			LOGD("LRU get connection %p %s:%d, last %d", bi->connection, hostname, (int)port, (int)bi->last_use);
			TAILQ_REMOVE(&ti->free_list, bi, tree_list_field); // remove from tree
			if (TAILQ_EMPTY(&ti->free_list)) {
				ti = RB_REMOVE(lru, &lru_head, ti); // list empty then erase tree item
				assert(ti);
				free(ti);
			}

			bi->parent = NULL;
			TAILQ_REMOVE(&queue, bi, queue_field); // remove from queue
			retval = bi->connection;
			evhtp_unset_hook(&bi->connection->hooks, evhtp_hook_on_conn_error);
			free(bi);
			return retval;
		}
	}

	return NULL;
}

void cache_put(const char *hostname, int port, evhtp_connection_t *conn)
{
	struct tree_item *ti;
	struct tree_item item;
	strcpy(item.hostname, hostname);
	item.port = port;

	ti = RB_FIND(lru, &lru_head, &item);
	if (ti == NULL) {
		ti = (struct tree_item *)calloc(1, sizeof(*ti));
		assert(ti);
		TAILQ_INIT(&ti->free_list);
		strcpy(ti->hostname, hostname);
		ti->port = port;

		if (RB_INSERT(lru, &lru_head, ti)) {
			assert(0);
		}
	}

	{
		struct connection_item *bi = (struct connection_item *)calloc(1, sizeof(struct connection_item));
		assert(bi);
		bi->connection = conn;
		bi->last_use = time(NULL);
		bi->parent = ti;
		TAILQ_INSERT_HEAD(&ti->free_list, bi, tree_list_field); // insert tree list

		// check clear timer
		if (TAILQ_EMPTY(&queue) && event_pending(timer_ev, EV_TIMEOUT, NULL) == 0) { 
			struct timeval timeout = {LRU_LIFE, 0};
			event_add(timer_ev, &timeout);
		}
		TAILQ_INSERT_HEAD(&queue, bi, queue_field); // insert into queue

		evhtp_set_hook(&bi->connection->hooks, evhtp_hook_on_conn_error, lru_conn_error, bi);
		LOGD("LRU put connection %p %s:%d, last %d", conn, hostname, (int)port, (int)bi->last_use);
	}

}

#ifndef TAILQ_FOREACH_REVERSE_SAFE
#define	TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)	\
	for ((var) = TAILQ_LAST((head), headname);			\
	(var) && ((tvar) = TAILQ_PREV((var), headname, field), 1);	\
	(var) = (tvar))
#endif

#ifndef RB_FOREACH_SAFE
#define RB_FOREACH_SAFE(x, name, head, tvar)				\
	for ((x) = RB_MIN(name, head);					\
	    ((x) != NULL) && ((tvar) = name ## _RB_NEXT(x), (x) != NULL);	\
	     (x) = (tvar))
#endif

static void clear_item(struct connection_item *bi, int error)
{
	LOGD("LRU clear connection %p %s:%d, last %d", bi->connection, bi->parent->hostname, (int)bi->parent->port, (int)bi->last_use);
	TAILQ_REMOVE(&bi->parent->free_list, bi, tree_list_field); // remove from tree free list

	if (TAILQ_EMPTY(&bi->parent->free_list)) {
		// empty tree item
		struct tree_item *ti;
		ti = RB_REMOVE(lru, &lru_head, bi->parent);
		assert(ti && ti == bi->parent);
		free(ti);
	}

	TAILQ_REMOVE(&queue, bi, queue_field); // remove from queue
	evhtp_unset_hook(&bi->connection->hooks, evhtp_hook_on_conn_error);
	if (!error)
		evhtp_connection_free(bi->connection);
	free(bi);
}

static void timercb(evutil_socket_t fd, short events, void *arg)
{
	struct connection_item *bi = NULL;
	struct connection_item *temp;
	time_t now = time(NULL);

	TAILQ_FOREACH_REVERSE_SAFE(bi, &queue, queue, queue_field, temp) {
		if (now < LRU_LIFE + bi->last_use)
			break;

		LOGE("LRU timeout connection %p %s:%d, last %d, now %d", bi->connection, bi->parent->hostname, (int)bi->parent->port, (int)bi->last_use, (int)now);
		clear_item(bi, 0);
	}

	if (!TAILQ_EMPTY(&queue))
	{
		bi = TAILQ_LAST(&queue, queue);
        struct timeval timeout = { .tv_sec = LRU_LIFE + bi->last_use - now, .tv_usec = 0 };
		event_add(timer_ev, &timeout);
	}
}

struct lru_connect_cb_arg
{
	lru_get_callback cb;
	evhtp_request_t *req;
};

static void lru_connect_cb(struct bufferevent *bev, void *arg)
{
	evhtp_connection_t *conn = NULL;
	struct lru_connect_cb_arg *connect_arg = (struct lru_connect_cb_arg*)arg;

	if (bev) {
		conn = evhtp_connection_new_from_bev(bev);
	} else {
		LOGE("lru_connect connect error");
	}

	connect_arg->cb(conn, connect_arg->req);
	free(connect_arg);
}

static evhtp_res lru_conn_error(evhtp_connection_t * connection, evhtp_error_flags errtype, void * arg)
{
	struct connection_item *bi = (struct connection_item *)arg;
	assert (bi && bi->parent && bi->connection == connection);
	LOGE("connection %p hook error %s:%d", connection, bi->parent->hostname, (int)bi->parent->port);
	clear_item(bi, 1);

	return EVHTP_RES_OK;
}

void lru_init(evbase_t *base)
{
	timer_ev = event_new(base, -1, 0, timercb, base);
}

void lru_fini()
{
    struct connection_item *bi = NULL;
    struct connection_item *temp;

    LOGD("LRU fini");
    TAILQ_FOREACH_REVERSE_SAFE(bi, &queue, queue, queue_field, temp) {
        clear_item(bi, 0);
    }

    if (timer_ev) {
        event_del(timer_ev);
        event_free(timer_ev);
    }
}

void lru_get(const char *host, uint16_t port, lru_get_callback cb, void *arg)
{
	evhtp_request_t * req = (evhtp_request_t *)arg;
	evhtp_connection_t *conn = cache_get(host, port);
	if (conn) {
		LOGD("get connection %p from cache %s:%d", conn, host, (int)port);
		cb(conn, arg);
	} else {
		struct lru_connect_cb_arg *connect_arg = 
			(struct lru_connect_cb_arg*)calloc(1, sizeof(struct lru_connect_cb_arg));
		connect_arg->cb = cb;
		connect_arg->req = req;
		connect_upstream(req->conn->evbase, evdns, host, port, lru_connect_cb, connect_arg); // async connect
	}
}

void lru_set(const char *host, uint16_t port, evhtp_connection_t *conn)
{
	cache_put(host, port, conn);
}
