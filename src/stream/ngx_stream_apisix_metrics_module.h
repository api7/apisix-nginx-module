#ifndef _NGX_STREAM_APISIX_METRICS_H_INCLUDED_
#define _NGX_STREAM_APISIX_METRICS_H_INCLUDED_


#include <ngx_stream.h>


/*
 * Byte counters kept per listening address. The direction is always named
 * from the gateway's point of view, matching the `type` label of the HTTP
 * side `apisix_bandwidth` metric: ingress is what the gateway receives,
 * egress is what the gateway sends.
 */
#define NGX_STREAM_APISIX_METRICS_DOWNSTREAM_INGRESS   0
#define NGX_STREAM_APISIX_METRICS_DOWNSTREAM_EGRESS    1
#define NGX_STREAM_APISIX_METRICS_UPSTREAM_EGRESS      2
#define NGX_STREAM_APISIX_METRICS_UPSTREAM_INGRESS     3
#define NGX_STREAM_APISIX_METRICS_DIRECTIONS           4

#define NGX_STREAM_APISIX_METRICS_ADDR_LEN             128

/*
 * Room for the label values of a session, which the Lua side joins into one
 * byte string: for instance an APISIX object id (at most 256 bytes) together
 * with its name
 */
#define NGX_STREAM_APISIX_METRICS_LABELS_LEN           512


/*
 * Why a session ended. nginx keeps `s->status` at 200 for every failure that
 * happens after the upstream connection is established, so the reasons below
 * are what the Lua side needs to tell a graceful close apart from a timeout
 * or a reset. Exposed as $stream_session_reason.
 */
typedef enum {
    NGX_STREAM_APISIX_REASON_UNSET = 0,
    NGX_STREAM_APISIX_REASON_CLOSED,
    NGX_STREAM_APISIX_REASON_CLIENT_RST,
    NGX_STREAM_APISIX_REASON_CLIENT_ERROR,
    NGX_STREAM_APISIX_REASON_UPSTREAM_RST,
    NGX_STREAM_APISIX_REASON_UPSTREAM_ERROR,
    NGX_STREAM_APISIX_REASON_CONNECT_TIMEOUT,
    NGX_STREAM_APISIX_REASON_RECV_TIMEOUT,
    NGX_STREAM_APISIX_REASON_SEND_TIMEOUT,
    NGX_STREAM_APISIX_REASON_UPSTREAM_TIMEOUT,
    NGX_STREAM_APISIX_REASON_SHUTDOWN,
    NGX_STREAM_APISIX_REASON_CONNECT_FAILED,
    NGX_STREAM_APISIX_REASON_CLIENT_READ_ERROR,
    NGX_STREAM_APISIX_REASON_UPSTREAM_READ_ERROR
} ngx_stream_apisix_reason_e;


/*
 * The layout Lua reads through FFI, one entry per listening address and set
 * of label values. The unlabelled entry of an address holds every session
 * that was never labelled.
 */
typedef struct {
    u_char        addr[NGX_STREAM_APISIX_METRICS_ADDR_LEN];
    uint32_t      addr_len;
    uint32_t      labels_len;
    u_char        labels[NGX_STREAM_APISIX_METRICS_LABELS_LEN];
    uint64_t      active;
    uint64_t      bytes[NGX_STREAM_APISIX_METRICS_DIRECTIONS];
} ngx_stream_apisix_metrics_entry_t;


/* called from the patched ngx_stream_proxy_module */
void ngx_stream_apisix_set_session_reason(ngx_stream_session_t *s,
    ngx_uint_t reason);
void ngx_stream_apisix_set_session_timeout_reason(ngx_stream_session_t *s);
void ngx_stream_apisix_set_connect_timeout(ngx_stream_session_t *s);
void ngx_stream_apisix_metrics_update(ngx_stream_session_t *s);
void ngx_stream_apisix_metrics_peer_closing(ngx_stream_session_t *s);
void ngx_stream_apisix_set_read_error(ngx_stream_session_t *s,
    ngx_uint_t from_upstream, ngx_err_t err);
void ngx_stream_apisix_metrics_finalize(ngx_stream_session_t *s,
    ngx_uint_t rc);

/* called from Lua through FFI */
ngx_int_t ngx_stream_apisix_metrics_dump(
    ngx_stream_apisix_metrics_entry_t *entries, ngx_uint_t max);
ngx_int_t ngx_stream_apisix_metrics_size(void);
ngx_int_t ngx_stream_apisix_metrics_set_labels(void *r, const u_char *labels,
    size_t len);


#endif /* _NGX_STREAM_APISIX_METRICS_H_INCLUDED_ */
