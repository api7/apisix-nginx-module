#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_stream_apisix_metrics_module.h"


/*
 * Counters are merged into the shared zone at most once per second, so a
 * long-lived session keeps the metrics moving without paying an atomic
 * operation per read/write. The pending delta is flushed when the session
 * ends, which keeps the totals exact.
 */
#define NGX_STREAM_APISIX_METRICS_FLUSH_INTERVAL   1

/*
 * One slot per stream listening address. A deployment has a handful of them,
 * the cap only keeps a huge zone from reserving a pointless amount of memory.
 */
#define NGX_STREAM_APISIX_METRICS_MAX_SLOTS        512


typedef struct {
    ngx_atomic_t    active;
    ngx_atomic_t    bytes[NGX_STREAM_APISIX_METRICS_DIRECTIONS];
    uint32_t        addr_len;
    u_char          addr[NGX_STREAM_APISIX_METRICS_ADDR_LEN];
} ngx_stream_apisix_metrics_slot_t;


typedef struct {
    ngx_uint_t                          nslots;
    ngx_uint_t                          nused;
    ngx_stream_apisix_metrics_slot_t   *slots;
} ngx_stream_apisix_metrics_sh_t;


typedef struct {
    ngx_shm_zone_t                     *shm_zone;
} ngx_stream_apisix_metrics_main_conf_t;


typedef struct {
    ngx_stream_apisix_metrics_slot_t   *slot;
    off_t                               flushed[NGX_STREAM_APISIX_METRICS_DIRECTIONS];
    time_t                              flush_time;
    ngx_uint_t                          reason;
    unsigned                            counted:1;
    unsigned                            connect_timeout:1;
    unsigned                            finalized:1;
} ngx_stream_apisix_metrics_ctx_t;


static ngx_int_t ngx_stream_apisix_metrics_preconf(ngx_conf_t *cf);
static ngx_int_t ngx_stream_apisix_metrics_postconf(ngx_conf_t *cf);
static void *ngx_stream_apisix_metrics_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_apisix_metrics_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_stream_apisix_metrics_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_stream_apisix_metrics_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_stream_apisix_metrics_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_stream_apisix_metrics_post_accept_handler(
    ngx_stream_session_t *s);
static ngx_int_t ngx_stream_apisix_metrics_log_handler(
    ngx_stream_session_t *s);
static ngx_int_t ngx_stream_apisix_session_reason_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_apisix_listen_addr_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_stream_apisix_metrics_cmds[] = {

    { ngx_string("apisix_stream_metrics_zone"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_stream_apisix_metrics_zone,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_apisix_metrics_module_ctx = {
    ngx_stream_apisix_metrics_preconf,       /* preconfiguration */
    ngx_stream_apisix_metrics_postconf,      /* postconfiguration */

    ngx_stream_apisix_metrics_create_main_conf, /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
};


ngx_module_t  ngx_stream_apisix_metrics_module = {
    NGX_MODULE_V1,
    &ngx_stream_apisix_metrics_module_ctx,   /* module context */
    ngx_stream_apisix_metrics_cmds,          /* module directives */
    NGX_STREAM_MODULE,                       /* module type */
    NULL,                                    /* init master */
    ngx_stream_apisix_metrics_init_module,   /* init module */
    ngx_stream_apisix_metrics_init_process,  /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_stream_apisix_metrics_zone_name =
    ngx_string("apisix_stream_metrics");


static ngx_stream_variable_t  ngx_stream_apisix_metrics_vars[] = {

    { ngx_string("stream_session_reason"), NULL,
      ngx_stream_apisix_session_reason_variable, 0,
      NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("stream_listen_addr"), NULL,
      ngx_stream_apisix_listen_addr_variable, 0,
      NGX_STREAM_VAR_NOCACHEABLE, 0 },

      ngx_stream_null_variable
};


static ngx_str_t  ngx_stream_apisix_reasons[] = {
    ngx_string("-"),
    ngx_string("closed"),
    ngx_string("client_rst"),
    ngx_string("client_error"),
    ngx_string("upstream_rst"),
    ngx_string("upstream_error"),
    ngx_string("connect_timeout"),
    ngx_string("recv_timeout"),
    ngx_string("send_timeout"),
    ngx_string("upstream_timeout"),
    ngx_string("shutdown")
};

#define NGX_STREAM_APISIX_REASONS_N                                          \
    (sizeof(ngx_stream_apisix_reasons) / sizeof(ngx_stream_apisix_reasons[0]))


/*
 * Rebound per cycle by ngx_stream_apisix_metrics_bind_zone(), so that the FFI
 * reader does not depend on a session, and so that a reload dropping the zone
 * cannot leave this pointing into unmapped shared memory.
 */
static ngx_stream_apisix_metrics_sh_t  *ngx_stream_apisix_metrics_sh = NULL;

/*
 * Maps a listening socket to its slot without a lookup on the hot path.
 * Rebuilt per cycle in init_process, so a reload picks up the new listen set.
 */
static ngx_stream_apisix_metrics_slot_t **ngx_stream_apisix_metrics_map = NULL;
static ngx_listening_t                   *ngx_stream_apisix_metrics_ls = NULL;
static ngx_uint_t                         ngx_stream_apisix_metrics_nls = 0;


static void *
ngx_stream_apisix_metrics_create_main_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_stream_apisix_metrics_main_conf_t));
}


static char *
ngx_stream_apisix_metrics_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_apisix_metrics_main_conf_t  *mcf = conf;

    ssize_t      size;
    ngx_str_t   *value;

    if (mcf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    size = ngx_parse_size(&value[1]);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone size \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "zone \"%V\" is too small",
                           &ngx_stream_apisix_metrics_zone_name);
        return NGX_CONF_ERROR;
    }

    mcf->shm_zone = ngx_shared_memory_add(cf,
                                          &ngx_stream_apisix_metrics_zone_name,
                                          size,
                                          &ngx_stream_apisix_metrics_module);
    if (mcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->shm_zone->init = ngx_stream_apisix_metrics_init_zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_apisix_metrics_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_stream_apisix_metrics_sh_t  *osh = data;

    ngx_uint_t                       nslots;
    ngx_slab_pool_t                 *shpool;
    ngx_stream_apisix_metrics_sh_t  *sh;

    if (osh) {
        /* reused on reload, the accumulated counters must survive */
        shm_zone->data = osh;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }

    /*
     * The slot array is sized once and never grows: the set of stream
     * listening addresses is fixed at configuration time. Only half of the
     * zone is handed out so that the slab bookkeeping always fits.
     */
    nslots = (shm_zone->shm.size - sizeof(ngx_slab_pool_t)) / 2
             / sizeof(ngx_stream_apisix_metrics_slot_t);

    if (nslots > NGX_STREAM_APISIX_METRICS_MAX_SLOTS) {
        nslots = NGX_STREAM_APISIX_METRICS_MAX_SLOTS;
    }

    sh = ngx_slab_calloc(shpool, sizeof(ngx_stream_apisix_metrics_sh_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    sh->slots = ngx_slab_calloc(shpool,
                    nslots * sizeof(ngx_stream_apisix_metrics_slot_t));
    if (sh->slots == NULL) {
        return NGX_ERROR;
    }

    sh->nslots = nslots;
    sh->nused = 0;

    shpool->data = sh;
    shm_zone->data = sh;

    return NGX_OK;
}


/*
 * Resolved per cycle rather than cached when the zone is created: a reload
 * that drops the directive (or the whole stream block) leaves no zone in the
 * new cycle, and ngx_init_cycle then unmaps the old one. A pointer kept from
 * the previous cycle would dangle into freed shared memory.
 */
static void
ngx_stream_apisix_metrics_bind_zone(ngx_cycle_t *cycle)
{
    ngx_stream_apisix_metrics_main_conf_t  *mcf;

    ngx_stream_apisix_metrics_sh = NULL;

    mcf = ngx_stream_cycle_get_module_main_conf(cycle,
                                            ngx_stream_apisix_metrics_module);

    if (mcf != NULL && mcf->shm_zone != NULL) {
        ngx_stream_apisix_metrics_sh = mcf->shm_zone->data;
    }
}


static ngx_stream_apisix_metrics_slot_t *
ngx_stream_apisix_metrics_lookup(ngx_str_t *addr, ngx_uint_t create)
{
    ngx_uint_t                         i;
    ngx_uint_t                         nused;
    ngx_stream_apisix_metrics_sh_t    *sh;
    ngx_stream_apisix_metrics_slot_t  *slot;

    sh = ngx_stream_apisix_metrics_sh;
    if (sh == NULL) {
        return NULL;
    }

    /*
     * Pair with the barrier the writer takes before publishing the count: the
     * slot contents must not be read before the count that exposes them.
     */
    nused = sh->nused;
    ngx_memory_barrier();

    for (i = 0; i < nused; i++) {
        slot = &sh->slots[i];

        if (slot->addr_len == addr->len
            && ngx_memcmp(slot->addr, addr->data, addr->len) == 0)
        {
            return slot;
        }
    }

    if (!create || nused == sh->nslots) {
        return NULL;
    }

    slot = &sh->slots[sh->nused];

    slot->addr_len = (uint32_t) addr->len;
    ngx_memcpy(slot->addr, addr->data, addr->len);

    /*
     * A reload reuses the zone, so the master appends here while the previous
     * generation of workers is still reading. Publish the contents before the
     * count that exposes them.
     */
    ngx_memory_barrier();

    sh->nused++;

    return slot;
}


/*
 * Only the master ever claims, and only by appending, so no lock is needed:
 * readers either see a slot fully or do not see it at all. On a reload the
 * previous generation of workers is still reading, which is what the barrier
 * in the lookup above is for.
 */
static ngx_int_t
ngx_stream_apisix_metrics_init_module(ngx_cycle_t *cycle)
{
    ngx_str_t          addr;
    ngx_uint_t         i;
    ngx_listening_t   *ls;

    ngx_stream_apisix_metrics_bind_zone(cycle);

    if (ngx_stream_apisix_metrics_sh == NULL) {
        return NGX_OK;
    }

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].handler != ngx_stream_init_connection) {
            continue;
        }

        /*
         * Unix sockets inside stream{} are internal plumbing, not proxy
         * ports: APISIX puts its worker event channel there, and counting it
         * would report gateway control traffic as proxied bytes and leave a
         * permanent floor of worker connections in the active gauge.
         */
#if (NGX_HAVE_UNIX_DOMAIN)
        if (ls[i].sockaddr->sa_family == AF_UNIX) {
            continue;
        }
#endif

        addr = ls[i].addr_text;

        if (addr.len == 0) {
            continue;
        }

        if (addr.len > NGX_STREAM_APISIX_METRICS_ADDR_LEN) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "apisix stream metrics: listening address \"%V\" is "
                          "longer than %d bytes and is not accounted for",
                          &addr, NGX_STREAM_APISIX_METRICS_ADDR_LEN);
            continue;
        }

        if (ngx_stream_apisix_metrics_lookup(&addr, 1) == NULL) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "apisix stream metrics zone is too small to hold "
                          "listening address \"%V\"", &addr);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_apisix_metrics_init_process(ngx_cycle_t *cycle)
{
    ngx_uint_t          i;
    ngx_listening_t    *ls;

    ngx_stream_apisix_metrics_map = NULL;
    ngx_stream_apisix_metrics_ls = NULL;
    ngx_stream_apisix_metrics_nls = 0;

    ngx_stream_apisix_metrics_bind_zone(cycle);

    if (ngx_stream_apisix_metrics_sh == NULL || cycle->listening.nelts == 0) {
        return NGX_OK;
    }

    ls = cycle->listening.elts;

    ngx_stream_apisix_metrics_map = ngx_pcalloc(cycle->pool,
        cycle->listening.nelts * sizeof(ngx_stream_apisix_metrics_slot_t *));
    if (ngx_stream_apisix_metrics_map == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].handler != ngx_stream_init_connection) {
            continue;
        }

        ngx_stream_apisix_metrics_map[i] =
            ngx_stream_apisix_metrics_lookup(&ls[i].addr_text, 0);
    }

    ngx_stream_apisix_metrics_ls = ls;
    ngx_stream_apisix_metrics_nls = cycle->listening.nelts;

    return NGX_OK;
}


static ngx_stream_apisix_metrics_slot_t *
ngx_stream_apisix_metrics_slot(ngx_connection_t *c)
{
    ngx_uint_t   i;

    if (ngx_stream_apisix_metrics_map == NULL || c->listening == NULL) {
        return NULL;
    }

    i = (ngx_uint_t) (c->listening - ngx_stream_apisix_metrics_ls);

    if (i >= ngx_stream_apisix_metrics_nls) {
        return NULL;
    }

    return ngx_stream_apisix_metrics_map[i];
}


static ngx_stream_apisix_metrics_ctx_t *
ngx_stream_apisix_metrics_get_ctx(ngx_stream_session_t *s)
{
    return ngx_stream_get_module_ctx(s, ngx_stream_apisix_metrics_module);
}


static ngx_int_t
ngx_stream_apisix_metrics_post_accept_handler(ngx_stream_session_t *s)
{
    ngx_stream_apisix_metrics_ctx_t   *ctx;
    ngx_stream_apisix_metrics_slot_t  *slot;

    /*
     * The context is always allocated: $stream_session_reason needs it to
     * carry the reasons recorded by the proxy module even when no metrics
     * zone is configured.
     */
    ctx = ngx_pcalloc(s->connection->pool,
                      sizeof(ngx_stream_apisix_metrics_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_apisix_metrics_module);

    slot = ngx_stream_apisix_metrics_slot(s->connection);
    if (slot == NULL) {
        return NGX_DECLINED;
    }

    ctx->slot = slot;
    ctx->counted = 1;

    (void) ngx_atomic_fetch_add(&slot->active, 1);

    return NGX_DECLINED;
}


static void
ngx_stream_apisix_metrics_flush(ngx_stream_session_t *s,
    ngx_stream_apisix_metrics_ctx_t *ctx, ngx_uint_t force)
{
    off_t                              current[NGX_STREAM_APISIX_METRICS_DIRECTIONS];
    off_t                              delta;
    ngx_uint_t                         i, flushed;
    ngx_connection_t                  *pc;
    ngx_stream_upstream_t             *u;
    ngx_stream_apisix_metrics_slot_t  *slot;

    slot = ctx->slot;
    if (slot == NULL) {
        return;
    }

    if (!force && ngx_time() - ctx->flush_time
                  < NGX_STREAM_APISIX_METRICS_FLUSH_INTERVAL)
    {
        return;
    }

    u = s->upstream;
    pc = (u && u->peer.connection) ? u->peer.connection : NULL;

    current[NGX_STREAM_APISIX_METRICS_DOWNSTREAM_INGRESS] = s->received;
    current[NGX_STREAM_APISIX_METRICS_DOWNSTREAM_EGRESS] = s->connection->sent;
    current[NGX_STREAM_APISIX_METRICS_UPSTREAM_EGRESS] = pc ? pc->sent : 0;
    current[NGX_STREAM_APISIX_METRICS_UPSTREAM_INGRESS] = u ? u->received : 0;

    flushed = 0;

    for (i = 0; i < NGX_STREAM_APISIX_METRICS_DIRECTIONS; i++) {
        delta = current[i] - ctx->flushed[i];

        /*
         * proxy_next_upstream replaces the peer connection, so pc->sent
         * restarts from zero while the flushed mark still holds the previous
         * peer's total. Treat any decrease as a restart and count what the
         * new counter holds, otherwise the retried bytes are lost.
         */
        if (delta < 0) {
            delta = current[i];
        }

        if (delta == 0) {
            continue;
        }

        (void) ngx_atomic_fetch_add(&slot->bytes[i], (ngx_atomic_int_t) delta);
        ctx->flushed[i] = current[i];
        flushed = 1;
    }

    /*
     * Only an actual write starts the interval. The proxy module calls in
     * once before any data has moved, and stamping the clock there would
     * hide the first bytes of the session for a whole second.
     */
    if (flushed) {
        ctx->flush_time = ngx_time();
    }
}


void
ngx_stream_apisix_metrics_update(ngx_stream_session_t *s)
{
    ngx_stream_apisix_metrics_ctx_t  *ctx;

    ctx = ngx_stream_apisix_metrics_get_ctx(s);
    if (ctx == NULL) {
        return;
    }

    ngx_stream_apisix_metrics_flush(s, ctx, 0);
}


/*
 * proxy_next_upstream is about to drop the peer, taking pc->sent with it.
 * Bank what it sent and reset the mark, otherwise the next peer starts from
 * zero below the old mark and the retried bytes are only recovered if that
 * counter happens to overtake it before the next sample.
 */
void
ngx_stream_apisix_metrics_peer_closing(ngx_stream_session_t *s)
{
    ngx_stream_apisix_metrics_ctx_t  *ctx;

    ctx = ngx_stream_apisix_metrics_get_ctx(s);
    if (ctx == NULL) {
        return;
    }

    ngx_stream_apisix_metrics_flush(s, ctx, 1);

    ctx->flushed[NGX_STREAM_APISIX_METRICS_UPSTREAM_EGRESS] = 0;
}


void
ngx_stream_apisix_set_session_reason(ngx_stream_session_t *s,
    ngx_uint_t reason)
{
    ngx_stream_apisix_metrics_ctx_t  *ctx;

    /*
     * The callers live in the ngx_stream_proxy_module patches, which are
     * separate files that can drift from this enum. The value indexes the
     * reason table, so refuse anything out of range rather than read past it.
     */
    if (reason >= NGX_STREAM_APISIX_REASONS_N) {
        return;
    }

    ctx = ngx_stream_apisix_metrics_get_ctx(s);
    if (ctx == NULL) {
        return;
    }

    /* the first terminating event wins, later ones are consequences of it */
    if (ctx->reason == NGX_STREAM_APISIX_REASON_UNSET) {
        ctx->reason = reason;
    }
}


/*
 * A connect timeout is not terminal on its own: nginx may still reach another
 * peer. It is only reported when the session really ended on a bad gateway.
 */
void
ngx_stream_apisix_set_connect_timeout(ngx_stream_session_t *s)
{
    ngx_stream_apisix_metrics_ctx_t  *ctx;

    ctx = ngx_stream_apisix_metrics_get_ctx(s);
    if (ctx == NULL) {
        return;
    }

    ctx->connect_timeout = 1;
}


/*
 * proxy_timeout is a single idle timeout shared by both directions. Data
 * still buffered towards a peer means that peer stopped reading, which is
 * what the product calls a send timeout; anything else is a receive timeout.
 */
void
ngx_stream_apisix_set_session_timeout_reason(ngx_stream_session_t *s)
{
    ngx_uint_t              reason;
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;

    u = s->upstream;
    pc = (u && u->peer.connection) ? u->peer.connection : NULL;

    if (s->connection->buffered || (pc && pc->buffered)) {
        reason = NGX_STREAM_APISIX_REASON_SEND_TIMEOUT;

    } else {
        reason = NGX_STREAM_APISIX_REASON_RECV_TIMEOUT;
    }

    ngx_stream_apisix_set_session_reason(s, reason);
}


/*
 * Reasons that nginx does not record itself are derived from the connection
 * flags: a reset leaves read->error set even though the proxy module turns it
 * into an EOF afterwards, and a failed write leaves error set on the
 * destination connection.
 */
static ngx_uint_t
ngx_stream_apisix_derive_reason(ngx_stream_session_t *s,
    ngx_stream_apisix_metrics_ctx_t *ctx, ngx_uint_t status)
{
    ngx_connection_t       *c, *pc;
    ngx_stream_upstream_t  *u;

    if (ctx && ctx->connect_timeout && status == NGX_STREAM_BAD_GATEWAY) {
        return NGX_STREAM_APISIX_REASON_CONNECT_TIMEOUT;
    }

    c = s->connection;
    u = s->upstream;
    pc = (u && u->peer.connection) ? u->peer.connection : NULL;

    if (c->read->error) {
        return NGX_STREAM_APISIX_REASON_CLIENT_RST;
    }

    if (pc && pc->read->error) {
        return NGX_STREAM_APISIX_REASON_UPSTREAM_RST;
    }

    if (c->error) {
        return NGX_STREAM_APISIX_REASON_CLIENT_ERROR;
    }

    if (pc && pc->error) {
        return NGX_STREAM_APISIX_REASON_UPSTREAM_ERROR;
    }

    if (c->read->eof || (pc && pc->read->eof)) {
        return NGX_STREAM_APISIX_REASON_CLOSED;
    }

    return NGX_STREAM_APISIX_REASON_UNSET;
}


/*
 * Called from the proxy module before it tears the upstream connection down:
 * by log time u->peer.connection is already NULL, so both the reason and the
 * last byte delta towards the upstream have to be taken here.
 */
void
ngx_stream_apisix_metrics_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_stream_apisix_metrics_ctx_t  *ctx;

    ctx = ngx_stream_apisix_metrics_get_ctx(s);
    if (ctx == NULL || ctx->finalized) {
        return;
    }

    ctx->finalized = 1;

    ngx_stream_apisix_metrics_flush(s, ctx, 1);

    if (ctx->reason == NGX_STREAM_APISIX_REASON_UNSET) {
        ctx->reason = ngx_stream_apisix_derive_reason(s, ctx, rc);
    }

    /*
     * A UDP session has no FIN to observe: ngx_udp_shared_recv never sets
     * read->eof, so a session that simply ran to completion would otherwise
     * report no reason at all.
     */
    if (ctx->reason == NGX_STREAM_APISIX_REASON_UNSET
        && rc == NGX_STREAM_OK)
    {
        ctx->reason = NGX_STREAM_APISIX_REASON_CLOSED;
    }
}


static ngx_int_t
ngx_stream_apisix_session_reason_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t                        reason_index;
    ngx_str_t                        *reason;
    ngx_stream_apisix_metrics_ctx_t  *ctx;

    ctx = ngx_stream_apisix_metrics_get_ctx(s);

    if (ctx && ctx->reason != NGX_STREAM_APISIX_REASON_UNSET) {
        reason_index = ctx->reason;

    } else {
        /* sessions rejected before proxy_pass never reach the finalize hook */
        reason_index = ngx_stream_apisix_derive_reason(s, ctx, s->status);
    }

    reason = &ngx_stream_apisix_reasons[reason_index];

    v->len = reason->len;
    v->data = reason->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


/*
 * The configured listening address, which is how the metrics zone keys its
 * slots. $server_addr holds the address the connection was accepted on, so on
 * a wildcard listen the two would not agree.
 */
static ngx_int_t
ngx_stream_apisix_listen_addr_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_listening_t  *ls;

    ls = s->connection->listening;

    if (ls == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ls->addr_text.len;
    v->data = ls->addr_text.data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_apisix_metrics_log_handler(ngx_stream_session_t *s)
{
    ngx_stream_apisix_metrics_ctx_t  *ctx;

    ctx = ngx_stream_apisix_metrics_get_ctx(s);
    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_stream_apisix_metrics_flush(s, ctx, 1);

    if (ctx->counted) {
        ctx->counted = 0;
        (void) ngx_atomic_fetch_add(&ctx->slot->active, -1);
    }

    return NGX_OK;
}


ngx_int_t
ngx_stream_apisix_metrics_dump(ngx_stream_apisix_metrics_entry_t *entries,
    ngx_uint_t max)
{
    ngx_uint_t                         i, j, n;
    ngx_stream_apisix_metrics_sh_t    *sh;
    ngx_stream_apisix_metrics_slot_t  *slot;

    sh = ngx_stream_apisix_metrics_sh;
    if (sh == NULL) {
        return NGX_ERROR;
    }

    /* see the matching barrier in ngx_stream_apisix_metrics_lookup() */
    n = sh->nused;
    ngx_memory_barrier();

    n = ngx_min(n, max);

    for (i = 0; i < n; i++) {
        slot = &sh->slots[i];

        entries[i].addr_len = ngx_min(slot->addr_len,
                                      NGX_STREAM_APISIX_METRICS_ADDR_LEN);
        ngx_memcpy(entries[i].addr, slot->addr, entries[i].addr_len);

        entries[i].active = (uint64_t) slot->active;

        for (j = 0; j < NGX_STREAM_APISIX_METRICS_DIRECTIONS; j++) {
            entries[i].bytes[j] = (uint64_t) slot->bytes[j];
        }
    }

    return (ngx_int_t) n;
}


static ngx_int_t
ngx_stream_apisix_metrics_preconf(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_apisix_metrics_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_apisix_metrics_postconf(ngx_conf_t *cf)
{
    ngx_stream_handler_pt          *h;
    ngx_stream_core_main_conf_t    *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_POST_ACCEPT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_apisix_metrics_post_accept_handler;

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_apisix_metrics_log_handler;

    return NGX_OK;
}
