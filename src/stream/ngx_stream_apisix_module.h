#ifndef _NGX_STREAM_APISIX_H_INCLUDED_
#define _NGX_STREAM_APISIX_H_INCLUDED_


#include <ngx_stream.h>

/*
 * This header is the single entry point the ngx_stream_proxy_module patches
 * include, so everything they call has to be reachable from here.
 */
#include <ngx_stream_apisix_metrics_module.h>


ngx_int_t ngx_stream_apisix_is_proxy_ssl_enabled(ngx_stream_session_t *s);

#if (NGX_STREAM_SSL)
void ngx_stream_apisix_set_upstream_ssl(ngx_stream_session_t *s,
    ngx_connection_t *c);

/* called by the patched ngx_stream_ssl_module once a server has its SSL_CTX */
ngx_int_t ngx_stream_apisix_ssl_session_ticket_bind(ngx_conf_t *cf,
    ngx_ssl_t *ssl);
#endif


#endif /* _NGX_STREAM_APISIX_H_INCLUDED_ */
