#ifndef _NGX_HTTP_APISIX_H_INCLUDED_
#define _NGX_HTTP_APISIX_H_INCLUDED_


#include <ngx_http.h>


typedef struct {
    ngx_flag_t      delay_client_max_body_check;
    ngx_int_t       apisix_request_id_var_index;

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
    ngx_http_log_handler_pt  orig_log_handler;
    unsigned             client_max_body_size_set:1;
    unsigned             mirror_enabled:1;
    unsigned             request_buffering:1;
    unsigned             request_buffering_set:1;
    unsigned             request_header_set:1;
    unsigned             header_filter_by_lua_skipped:1;
    unsigned             body_filter_by_lua_skipped:1;
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

ngx_int_t ngx_http_apisix_is_header_filter_by_lua_skipped(ngx_http_request_t *r);
ngx_int_t ngx_http_apisix_is_body_filter_by_lua_skipped(ngx_http_request_t *r);

ngx_flag_t ngx_http_apisix_is_ntls_enabled(ngx_http_conf_ctx_t *conf_ctx);

char * ngx_http_apisix_error_log_request_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char * ngx_http_apisix_error_log_init(ngx_conf_t *cf);
char * ngx_http_apisix_error_log_request_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#endif /* _NGX_HTTP_APISIX_H_INCLUDED_ */
