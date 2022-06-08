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
    ngx_uint_t             *proxy_ignore_headers;
    ngx_hash_t              hide_headers_hash;
    ngx_array_t            *hide_headers;

    unsigned             client_max_body_size_set:1;
    unsigned             mirror_enabled:1;
    unsigned             request_buffering:1;
    unsigned             request_buffering_set:1;
    unsigned             request_header_set:1;
} ngx_http_apisix_ctx_t;


void ngx_http_apisix_set_upstream_ssl(ngx_http_request_t *r, ngx_connection_t *c);

ngx_flag_t ngx_http_apisix_delay_client_max_body_check(ngx_http_request_t *r);
off_t ngx_http_apisix_client_max_body_size(ngx_http_request_t *r);

ngx_int_t ngx_http_apisix_is_gzip_set(ngx_http_request_t *r);
ngx_int_t ngx_http_apisix_get_gzip_buffer_conf(ngx_http_request_t *r,
    ngx_int_t *num, size_t *size);
ngx_int_t ngx_http_apisix_get_gzip_compress_level(ngx_http_request_t *r);

ngx_int_t ngx_http_apisix_is_mirror_enabled(ngx_http_request_t *r);


ngx_int_t ngx_http_apisix_is_request_buffering(ngx_http_request_t *r, ngx_flag_t static_conf);

void ngx_http_apisix_mark_request_header_set(ngx_http_request_t *r);

ngx_int_t ngx_http_apisix_is_proxy_ignore_headers_set(ngx_http_request_t *r);
ngx_int_t ngx_http_apisix_get_proxy_ignore_headers(ngx_http_request_t *r, ngx_uint_t * mask);
ngx_int_t ngx_http_apisix_set_proxy_ignore_headers(ngx_http_request_t *r, ngx_uint_t mask);


ngx_int_t ngx_http_apisix_is_proxy_hide_headers_set(ngx_http_request_t *r);
ngx_int_t ngx_http_apisix_in_proxy_hide_headers(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t *in);
ngx_int_t ngx_http_apisix_set_proxy_hide_headers(ngx_http_request_t *r, ngx_str_t* hide_headers);

#endif /* _NGX_HTTP_APISIX_H_INCLUDED_ */
