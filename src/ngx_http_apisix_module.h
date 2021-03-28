#ifndef _NGX_HTTP_APISIX_H_INCLUDED_
#define _NGX_HTTP_APISIX_H_INCLUDED_


#include <ngx_http.h>


typedef struct {
    STACK_OF(X509)      *upstream_cert;
    EVP_PKEY            *upstream_pkey;
} ngx_http_apisix_ctx_t;


void ngx_http_apisix_set_upstream_ssl(ngx_http_request_t *r, ngx_connection_t *c);


#endif /* _NGX_HTTP_APISIX_H_INCLUDED_ */
