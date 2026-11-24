#ifndef _NGX_APISIX_SSL_SESSION_TICKET_H_INCLUDED_
#define _NGX_APISIX_SSL_SESSION_TICKET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * Takes over the session ticket keys of the SSL_CTX of an http or a stream
 * server marked with apisix_ssl_session_ticket_takeover: the context then
 * encrypts and decrypts tickets with a complete, ordered set of keys that
 * Lua installs, instead of the keys nginx generates or reads from files.
 *
 * nginx itself is hooked by the nginx-ssl_session_ticket_takeover patch,
 * which defines NGX_APISIX_SSL_SESSION_TICKET. Without it nothing is taken
 * over, the directive has no effect and the FFI reports the takeover as not
 * supported.
 */


/* a key in the nginx layout: name(16) | HMAC-SHA256(32) | AES-256-CBC(32) */
#define NGX_APISIX_SSL_SESSION_TICKET_KEY_SIZE  80
#define NGX_APISIX_SSL_SESSION_TICKET_MAX_KEYS  256


/* the layouts Lua reads through FFI */

typedef struct {
    uint32_t            id;
    /* the callback is registered on this context, for this generation */
    uint32_t            registered;
    /* SSL_OP_NO_TICKET is clear on the context */
    uint32_t            tickets;
    uint32_t            nkeys;
    uint64_t            generation;
    /* where the directive is, for diagnostics */
    const u_char       *conf;
    size_t              conf_len;
} ngx_apisix_ssl_session_ticket_info_t;


typedef struct {
    /* the context the handshake of the connection started with */
    uint32_t            id;
    /* SSL_OP_NO_TICKET is clear on the connection */
    uint32_t            tickets;
} ngx_apisix_ssl_session_ticket_conn_t;


typedef struct ngx_apisix_ssl_session_ticket_s  ngx_apisix_ssl_session_ticket_t;


char *ngx_apisix_ssl_session_ticket_takeover(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf, ngx_str_t *location);

#if (NGX_APISIX_SSL_SESSION_TICKET)
ngx_int_t ngx_apisix_ssl_session_ticket_bind(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *contexts, ngx_str_t *location);
#endif

/* called from Lua through FFI */
void ngx_apisix_ssl_session_ticket_info(ngx_apisix_ssl_session_ticket_t *t,
    ngx_apisix_ssl_session_ticket_info_t *info);
ngx_int_t ngx_apisix_ssl_session_ticket_set_keys(
    ngx_apisix_ssl_session_ticket_t *t, const u_char *keys, size_t len,
    char **err);
ngx_int_t ngx_apisix_ssl_session_ticket_revoke_keys(
    ngx_apisix_ssl_session_ticket_t *t);
ngx_int_t ngx_apisix_ssl_session_ticket_set_tickets(
    ngx_apisix_ssl_session_ticket_t *t, int on, char **err);
ngx_int_t ngx_apisix_ssl_session_ticket_connection(void *ssl_conn, int sync,
    ngx_apisix_ssl_session_ticket_conn_t *conn, char **err);

/* the configuration generation of this process, see ngx_http_apisix_module.c */
ngx_uint_t ngx_apisix_get_generation(void);


#endif /* _NGX_APISIX_SSL_SESSION_TICKET_H_INCLUDED_ */
