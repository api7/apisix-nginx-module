#ifndef _NGX_STREAM_APISIX_H_INCLUDED_
#define _NGX_STREAM_APISIX_H_INCLUDED_


#include <ngx_stream.h>


ngx_int_t ngx_stream_apisix_is_proxy_ssl_enabled(ngx_stream_session_t *s);

#if (NGX_STREAM_SSL)
void ngx_stream_apisix_set_upstream_ssl(ngx_stream_session_t *s,
    ngx_connection_t *c);
#endif


#endif /* _NGX_STREAM_APISIX_H_INCLUDED_ */
