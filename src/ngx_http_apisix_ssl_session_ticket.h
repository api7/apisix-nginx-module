#ifndef _NGX_HTTP_APISIX_SSL_SESSION_TICKET_H_INCLUDED_
#define _NGX_HTTP_APISIX_SSL_SESSION_TICKET_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    u_char       raw[80];
    int64_t      encrypt_from;
    int64_t      encrypt_until;
    int64_t      decrypt_until;
    uint32_t     lifetime;
} ngx_http_apisix_ticket_key_t;

ngx_int_t ngx_http_apisix_ssl_session_ticket_init(void);
void ngx_http_apisix_ssl_session_ticket_exit(ngx_cycle_t *cycle);

#endif
