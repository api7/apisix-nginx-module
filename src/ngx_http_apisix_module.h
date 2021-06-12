#ifndef _NGX_HTTP_APISIX_H_INCLUDED_
#define _NGX_HTTP_APISIX_H_INCLUDED_


#include <ngx_http.h>


typedef struct {
    ngx_flag_t      delay_client_max_body_check;
} ngx_http_apisix_loc_conf_t;


typedef struct {
    STACK_OF(X509)      *upstream_cert;
    EVP_PKEY            *upstream_pkey;

    off_t                client_max_body_size;

    unsigned             client_max_body_size_set:1;
} ngx_http_apisix_ctx_t;


void ngx_http_apisix_set_upstream_ssl(ngx_http_request_t *r, ngx_connection_t *c);

ngx_flag_t ngx_http_apisix_delay_client_max_body_check(ngx_http_request_t *r);
off_t ngx_http_apisix_client_max_body_size(ngx_http_request_t *r);


#endif /* _NGX_HTTP_APISIX_H_INCLUDED_ */
