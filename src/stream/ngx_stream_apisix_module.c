#include <ngx_stream.h>
#include <ngx_stream_lua_api.h>
#include "ngx_stream_apisix_module.h"
#include "../ngx_apisix_ssl_session_ticket.h"


typedef struct {
#if (NGX_STREAM_SSL)
    STACK_OF(X509)      *upstream_cert;
    EVP_PKEY            *upstream_pkey;
#endif
    unsigned             proxy_ssl_enabled:1;
} ngx_stream_apisix_ctx_t;


typedef struct {
    /* the servers marked with apisix_ssl_session_ticket_takeover */
    ngx_array_t          ssl_session_tickets;
} ngx_stream_apisix_main_conf_t;


typedef struct {
    ngx_flag_t           ssl_session_ticket_takeover;
    ngx_str_t            ssl_session_ticket_location;
} ngx_stream_apisix_srv_conf_t;


static void *ngx_stream_apisix_create_main_conf(ngx_conf_t *cf);
static void *ngx_stream_apisix_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_apisix_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_apisix_ssl_session_ticket_takeover(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_stream_apisix_cmds[] = {

    /* only in server{}: each TLS terminating server is marked on its own */
    { ngx_string("apisix_ssl_session_ticket_takeover"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_apisix_ssl_session_ticket_takeover,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_apisix_srv_conf_t, ssl_session_ticket_takeover),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t ngx_stream_apisix_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    ngx_stream_apisix_create_main_conf,      /* create main configuration */
    NULL,                                    /* init main configuration */

    ngx_stream_apisix_create_srv_conf,       /* create server configuration */
    ngx_stream_apisix_merge_srv_conf,        /* merge server configuration */
};


ngx_module_t ngx_stream_apisix_module = {
    NGX_MODULE_V1,
    &ngx_stream_apisix_module_ctx,       /* module context */
    ngx_stream_apisix_cmds,              /* module directives */
    NGX_STREAM_MODULE,                   /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_stream_apisix_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_apisix_main_conf_t  *amcf;

    amcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_apisix_main_conf_t));
    if (amcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&amcf->ssl_session_tickets, cf->pool, 1, sizeof(void *))
        != NGX_OK)
    {
        return NULL;
    }

    return amcf;
}


static void *
ngx_stream_apisix_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_apisix_srv_conf_t  *ascf;

    ascf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_apisix_srv_conf_t));
    if (ascf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     ascf->ssl_session_ticket_location = { 0, NULL };
     */

    ascf->ssl_session_ticket_takeover = NGX_CONF_UNSET;

    return ascf;
}


static char *
ngx_stream_apisix_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_apisix_srv_conf_t  *conf = child;

    /* not inherited: each server is marked on its own */
    ngx_conf_init_value(conf->ssl_session_ticket_takeover, 0);

    return NGX_CONF_OK;
}


static char *
ngx_stream_apisix_ssl_session_ticket_takeover(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
#if (NGX_HTTP_APISIX)
    ngx_stream_apisix_srv_conf_t  *ascf = conf;

    return ngx_apisix_ssl_session_ticket_takeover(cf, cmd, conf,
                                          &ascf->ssl_session_ticket_location);
#else
    /* the takeover lives in the http addon of this module */
    return ngx_conf_set_flag_slot(cf, cmd, conf);
#endif
}


#if (NGX_STREAM_SSL)

ngx_int_t
ngx_stream_apisix_ssl_session_ticket_bind(ngx_conf_t *cf, ngx_ssl_t *ssl)
{
#if (NGX_APISIX_SSL_SESSION_TICKET)
    ngx_stream_apisix_srv_conf_t   *ascf;
    ngx_stream_apisix_main_conf_t  *amcf;

    /*
     * cf holds the configuration of the server being merged; the mark is only
     * ever set in that server, so this module needs no merge of its own first
     */

    ascf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_apisix_module);

    if (ascf->ssl_session_ticket_takeover != 1) {
        return NGX_OK;
    }

    amcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_apisix_module);

    return ngx_apisix_ssl_session_ticket_bind(cf, ssl,
                                          &amcf->ssl_session_tickets,
                                          &ascf->ssl_session_ticket_location);
#else
    return NGX_OK;
#endif
}

#endif


/* the number of marked servers in this worker, NGX_DECLINED if unsupported */
ngx_int_t
ngx_stream_apisix_ssl_session_ticket_count(void)
{
#if (NGX_APISIX_SSL_SESSION_TICKET)
    ngx_stream_apisix_main_conf_t  *amcf;

    amcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle,
                                                 ngx_stream_apisix_module);
    if (amcf == NULL) {
        return 0;
    }

    return amcf->ssl_session_tickets.nelts;
#else
    return NGX_DECLINED;
#endif
}


/* the marked server with this 1-based id, in the order of the configuration */
void *
ngx_stream_apisix_ssl_session_ticket_get(ngx_uint_t id)
{
#if (NGX_APISIX_SSL_SESSION_TICKET)
    void                          **t;
    ngx_stream_apisix_main_conf_t  *amcf;

    amcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle,
                                                 ngx_stream_apisix_module);
    if (amcf == NULL || id == 0 || id > amcf->ssl_session_tickets.nelts) {
        return NULL;
    }

    t = amcf->ssl_session_tickets.elts;

    return t[id - 1];
#else
    return NULL;
#endif
}


#if (NGX_STREAM_SSL)

static X509 *
ngx_stream_apisix_x509_copy(const X509 *in)
{
    return X509_up_ref((X509 *) in) == 0 ? NULL : (X509 *) in;
}


static void
ngx_stream_apisix_flush_ssl_error(void)
{
    ERR_clear_error();
}


static void
ngx_stream_apisix_cleanup_cert_and_key(ngx_stream_apisix_ctx_t *ctx)
{
    if (ctx->upstream_cert != NULL) {
        sk_X509_pop_free(ctx->upstream_cert, X509_free);
        EVP_PKEY_free(ctx->upstream_pkey);

        ctx->upstream_cert = NULL;
        ctx->upstream_pkey = NULL;
    }
}


static void
ngx_stream_apisix_cleanup(void *data)
{
    ngx_stream_apisix_ctx_t     *ctx = data;

    ngx_stream_apisix_cleanup_cert_and_key(ctx);
}

#endif


static ngx_stream_apisix_ctx_t *
ngx_stream_apisix_get_module_ctx(ngx_stream_lua_request_t *r)
{
    ngx_stream_apisix_ctx_t     *ctx;
#if (NGX_STREAM_SSL)
    ngx_pool_cleanup_t          *cln;
#endif

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_apisix_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_stream_apisix_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

#if (NGX_STREAM_SSL)
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NULL;
        }

        cln->data = ctx;
        cln->handler = ngx_stream_apisix_cleanup;
#endif

        ngx_stream_lua_set_ctx(r, ctx, ngx_stream_apisix_module);
    }

    return ctx;
}


ngx_int_t
ngx_stream_apisix_upstream_enable_tls(ngx_stream_lua_request_t *r)
{
    ngx_stream_apisix_ctx_t       *ctx;

    ctx = ngx_stream_apisix_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->proxy_ssl_enabled = 1;

    return NGX_OK;
}


ngx_int_t
ngx_stream_apisix_is_proxy_ssl_enabled(ngx_stream_session_t *s)
{
    ngx_stream_apisix_ctx_t       *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_apisix_module);

    return ctx != NULL && ctx->proxy_ssl_enabled;
}


#if (NGX_STREAM_SSL)

ngx_int_t
ngx_stream_apisix_upstream_set_cert_and_key(ngx_stream_lua_request_t *r,
                                            void *data_cert, void *data_key)
{
    STACK_OF(X509)                *cert = data_cert;
    EVP_PKEY                      *key = data_key;
    STACK_OF(X509)                *new_chain;
    ngx_stream_apisix_ctx_t       *ctx;

    if (cert == NULL || key == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_stream_apisix_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->upstream_cert != NULL) {
        ngx_stream_apisix_cleanup_cert_and_key(ctx);
    }

    if (EVP_PKEY_up_ref(key) == 0) {
        goto failed;
    }

    new_chain = sk_X509_deep_copy(cert, ngx_stream_apisix_x509_copy,
                                  X509_free);
    if (new_chain == NULL) {
        EVP_PKEY_free(key);
        goto failed;
    }

    ctx->upstream_cert = new_chain;
    ctx->upstream_pkey = key;

    return NGX_OK;

failed:

    ngx_stream_apisix_flush_ssl_error();

    return NGX_ERROR;
}


void
ngx_stream_apisix_set_upstream_ssl(ngx_stream_session_t *s, ngx_connection_t *c)
{
    ngx_ssl_conn_t                *sc = c->ssl->connection;
    ngx_stream_apisix_ctx_t       *ctx;
    STACK_OF(X509)                *cert;
    EVP_PKEY                      *pkey;
    X509                          *x509;
#ifdef OPENSSL_IS_BORINGSSL
    size_t                         i;
#else
    int                            i;
#endif

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_apisix_module);

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "skip overriding upstream SSL configuration, "
                       "module ctx not set");
        return;
    }

    if (ctx->upstream_cert != NULL) {
        cert = ctx->upstream_cert;
        pkey = ctx->upstream_pkey;

        if (sk_X509_num(cert) < 1) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "invalid client certificate provided while "
                          "handshaking with upstream");
            goto failed;
        }

        x509 = sk_X509_value(cert, 0);
        if (x509 == NULL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "sk_X509_value() failed");
            goto failed;
        }

        if (SSL_use_certificate(sc, x509) == 0) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "SSL_use_certificate() failed");
            goto failed;
        }

        for (i = 1; i < sk_X509_num(cert); i++) {
            x509 = sk_X509_value(cert, i);
            if (x509 == NULL) {
                ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                              "sk_X509_value() failed");
                goto failed;
            }

            if (SSL_add1_chain_cert(sc, x509) == 0) {
                ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                              "SSL_add1_chain_cert() failed");
                goto failed;
            }
        }

        if (SSL_use_PrivateKey(sc, pkey) == 0) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "SSL_use_PrivateKey() failed");
            goto failed;
        }
    }

    return;

failed:

    ngx_stream_apisix_flush_ssl_error();
}

#endif
