#ifndef _NGX_HTTP_APISIX_H_INCLUDED_
#define _NGX_HTTP_APISIX_H_INCLUDED_


#include <ngx_http.h>


typedef struct {
    ngx_flag_t      delay_client_max_body_check;
} ngx_http_apisix_loc_conf_t;


typedef struct {
    ngx_int_t       buffer_num;
    size_t          buffer_size;
    ngx_int_t       level;
} ngx_http_apisix_gzip_t;


typedef struct {
    STACK_OF(X509)      *upstream_cert;
    EVP_PKEY            *upstream_pkey;

    off_t                client_max_body_size;

    ngx_http_apisix_gzip_t *gzip;

    unsigned             client_max_body_size_set:1;
    unsigned             mirror_enabled:1;
} ngx_http_apisix_ctx_t;


void ngx_http_apisix_set_upstream_ssl(ngx_http_request_t *r, ngx_connection_t *c);

ngx_flag_t ngx_http_apisix_delay_client_max_body_check(ngx_http_request_t *r);
off_t ngx_http_apisix_client_max_body_size(ngx_http_request_t *r);

ngx_int_t ngx_http_apisix_is_gzip_set(ngx_http_request_t *r);
ngx_int_t ngx_http_apisix_get_gzip_buffer_conf(ngx_http_request_t *r,
    ngx_int_t *num, size_t *size);
ngx_int_t ngx_http_apisix_get_gzip_compress_level(ngx_http_request_t *r);

ngx_int_t ngx_http_apisix_is_mirror_enabled(ngx_http_request_t *r);


#endif /* _NGX_HTTP_APISIX_H_INCLUDED_ */
