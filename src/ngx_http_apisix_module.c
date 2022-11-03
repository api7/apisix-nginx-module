#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_realip_module.h>
#include "ngx_http_apisix_module.h"


#define NGX_HTTP_APISIX_SSL_ENC     1
#define NGX_HTTP_APISIX_SSL_SIGN    2


static ngx_str_t remote_addr = ngx_string("remote_addr");
static ngx_str_t remote_port = ngx_string("remote_port");
static ngx_str_t realip_remote_addr = ngx_string("realip_remote_addr");
static ngx_str_t realip_remote_port = ngx_string("realip_remote_port");


static void *ngx_http_apisix_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_apisix_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t ngx_http_apisix_cmds[] = {
    { ngx_string("apisix_delay_client_max_body_check"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_apisix_loc_conf_t, delay_client_max_body_check),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_apisix_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_apisix_create_loc_conf,         /* create location configuration */
    ngx_http_apisix_merge_loc_conf           /* merge location configuration */
};


ngx_module_t ngx_http_apisix_module = {
    NGX_MODULE_V1,
    &ngx_http_apisix_module_ctx,         /* module context */
    ngx_http_apisix_cmds,                /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
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
ngx_http_apisix_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_apisix_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_apisix_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->delay_client_max_body_check = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_apisix_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_apisix_loc_conf_t *prev = parent;
    ngx_http_apisix_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->delay_client_max_body_check,
                         prev->delay_client_max_body_check, 0);

    return NGX_CONF_OK;
}


#if (NGX_HTTP_SSL)
static X509 *
ngx_http_apisix_x509_copy(const X509 *in)
{
    return X509_up_ref((X509 *) in) == 0 ? NULL : (X509 *) in;
}


static void
ngx_http_apisix_flush_ssl_error()
{
    ERR_clear_error();
}


static void
ngx_http_apisix_cleanup_cert_and_key(ngx_http_apisix_ctx_t *ctx)
{
    if (ctx->upstream_cert != NULL) {
        sk_X509_pop_free(ctx->upstream_cert, X509_free);
        EVP_PKEY_free(ctx->upstream_pkey);

        ctx->upstream_cert = NULL;
        ctx->upstream_pkey = NULL;
    }
}
#endif


static void
ngx_http_apisix_cleanup(void *data)
{
    ngx_http_apisix_ctx_t     *ctx = data;

#if (NGX_HTTP_SSL)
    ngx_http_apisix_cleanup_cert_and_key(ctx);
#endif
}


static ngx_http_apisix_ctx_t *
ngx_http_apisix_get_module_ctx(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t     *ctx;
    ngx_pool_cleanup_t        *cln;

    ctx = ngx_http_get_module_ctx(r, ngx_http_apisix_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_apisix_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NULL;
        }

        cln->data = ctx;
        cln->handler = ngx_http_apisix_cleanup;

        ngx_http_set_ctx(r, ctx, ngx_http_apisix_module);
    }

    return ctx;
}


#if (NGX_HTTP_SSL)


ngx_int_t
ngx_http_apisix_upstream_set_cert_and_key(ngx_http_request_t *r,
                                          void *data_cert, void *data_key)
{
    STACK_OF(X509)              *cert = data_cert;
    EVP_PKEY                    *key = data_key;
    STACK_OF(X509)              *new_chain;
    ngx_http_apisix_ctx_t       *ctx;

    if (cert == NULL || key == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_apisix_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->upstream_cert != NULL) {
        ngx_http_apisix_cleanup_cert_and_key(ctx);
    }

    if (EVP_PKEY_up_ref(key) == 0) {
        goto failed;
    }

    new_chain = sk_X509_deep_copy(cert, ngx_http_apisix_x509_copy,
                                  X509_free);
    if (new_chain == NULL) {
        EVP_PKEY_free(key);
        goto failed;
    }

    ctx->upstream_cert = new_chain;
    ctx->upstream_pkey = key;

    return NGX_OK;

failed:

    ngx_http_apisix_flush_ssl_error();

    return NGX_ERROR;
}


void
ngx_http_apisix_set_upstream_ssl(ngx_http_request_t *r, ngx_connection_t *c)
{
    ngx_ssl_conn_t              *sc = c->ssl->connection;
    ngx_http_apisix_ctx_t       *ctx;
    STACK_OF(X509)              *cert;
    EVP_PKEY                    *pkey;
    X509                        *x509;
#ifdef OPENSSL_IS_BORINGSSL
    size_t                       i;
#else
    int                          i;
#endif

    ctx = ngx_http_get_module_ctx(r, ngx_http_apisix_module);

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
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

    ngx_http_apisix_flush_ssl_error();
}
#endif


ngx_flag_t
ngx_http_apisix_delay_client_max_body_check(ngx_http_request_t *r)
{
    ngx_http_apisix_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_apisix_module);
    return alcf->delay_client_max_body_check;
}


ngx_int_t
ngx_http_apisix_client_set_max_body_size(ngx_http_request_t *r,
                                         off_t bytes)
{
    ngx_http_apisix_ctx_t       *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "set client max body size %O",
                   bytes);

    ctx->client_max_body_size = bytes;
    ctx->client_max_body_size_set = 1;

    return NGX_OK;
}


off_t
ngx_http_apisix_client_max_body_size(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t     *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_apisix_module);

    if (ctx != NULL && ctx->client_max_body_size_set) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "get client max body size %O",
                       ctx->client_max_body_size);
        return ctx->client_max_body_size;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    return clcf->client_max_body_size;
}


ngx_int_t
ngx_http_apisix_is_gzip_set(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r->main);
    if (ctx == NULL || ctx->gzip == NULL) {
        return 0;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "apisix gzip set");

    return 1;
}


ngx_int_t
ngx_http_apisix_get_gzip_buffer_conf(ngx_http_request_t *r, ngx_int_t *num,
    size_t *size)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r->main);
    if (ctx == NULL || ctx->gzip == NULL) {
        return NGX_DECLINED;
    }

    *num = ctx->gzip->buffer_num;
    *size = ctx->gzip->buffer_size;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "apisix gzip num:%i size:%z", *num, *size);

    return NGX_OK;
}


ngx_int_t
ngx_http_apisix_get_gzip_compress_level(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r->main);
    if (ctx == NULL || ctx->gzip == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "apisix gzip level:%i", ctx->gzip->level);

    return ctx->gzip->level;
}


ngx_int_t
ngx_http_apisix_set_gzip(ngx_http_request_t *r, ngx_int_t num, size_t size,
    ngx_int_t level)
{
    ngx_http_apisix_ctx_t          *ctx;
    ngx_http_apisix_gzip_t         *gzip;

    ctx = ngx_http_apisix_get_module_ctx(r->main);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    gzip = ngx_palloc(r->pool, sizeof(ngx_http_apisix_gzip_t));
    if (gzip == NULL) {
        return NGX_ERROR;
    }

    gzip->level = level;
    gzip->buffer_num = num;
    gzip->buffer_size = size;

    ctx->gzip = gzip;
    return NGX_OK;
}


ngx_int_t
ngx_http_apisix_flush_var(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t                  hash;
    ngx_http_variable_t        *v;
    ngx_http_variable_value_t  *vv;
    ngx_http_core_main_conf_t  *cmcf;

    hash = ngx_hash_key(name->data, name->len);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    v = ngx_hash_find(&cmcf->variables_hash, hash, name->data, name->len);

    if (v) {
        vv = &r->variables[v->index];
        vv->valid = 0;

        return NGX_OK;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_apisix_set_real_ip(ngx_http_request_t *r, const u_char *text, size_t len,
                            unsigned int port)
{
    ngx_int_t           rc;
    ngx_addr_t          addr;

    rc = ngx_parse_addr(r->connection->pool, &addr, (u_char *) text, len);
    if (rc != NGX_OK) {
        return rc;
    }

    if (port == 0) {
        port = ngx_inet_get_port(r->connection->sockaddr);
    }
    ngx_inet_set_port(addr.sockaddr, (in_port_t) port);

    rc = ngx_http_realip_set_real_addr(r, &addr);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    ngx_http_apisix_flush_var(r, &remote_addr);
    ngx_http_apisix_flush_var(r, &remote_port);
    ngx_http_apisix_flush_var(r, &realip_remote_addr);
    ngx_http_apisix_flush_var(r, &realip_remote_port);

    return NGX_OK;
}


ngx_int_t
ngx_http_apisix_enable_mirror(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t       *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->mirror_enabled = 1;
    return NGX_OK;
}


ngx_int_t
ngx_http_apisix_is_mirror_enabled(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);
    return ctx != NULL && ctx->mirror_enabled;
}


ngx_int_t
ngx_http_apisix_set_proxy_request_buffering(ngx_http_request_t *r, int on)
{
    ngx_http_apisix_ctx_t       *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->request_buffering = on;
    ctx->request_buffering_set = 1;
    return NGX_OK;
}


ngx_int_t
ngx_http_apisix_is_request_buffering(ngx_http_request_t *r, ngx_flag_t static_conf)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);

    if (ctx != NULL && ctx->request_buffering_set) {
        return ctx->request_buffering;
    }

    /* use the static conf if we haven't changed it dynamically */
    return static_conf;
}


ngx_int_t
ngx_http_apisix_is_request_header_set(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);

    if (ctx != NULL) {
        return ctx->request_header_set;
    }

    return 0;
}


void
ngx_http_apisix_clear_request_header(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);

    if (ctx != NULL) {
        ctx->request_header_set = 0;
    }
}


void
ngx_http_apisix_mark_request_header_set(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no memory to mark request headers");
        return;
    }

    ctx->request_header_set = 1;
}


ngx_int_t
ngx_http_apisix_skip_header_filter_by_lua(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->header_filter_by_lua_skipped = 1;
    return NGX_OK;
}


ngx_int_t
ngx_http_apisix_is_header_filter_by_lua_skipped(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);
    if (ctx != NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "apisix header_filter_by_lua %p skipped: %d",
                       ctx, ctx->header_filter_by_lua_skipped);

        return ctx->header_filter_by_lua_skipped;
    }

    return 0;
}


ngx_int_t
ngx_http_apisix_skip_body_filter_by_lua(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->body_filter_by_lua_skipped = 1;
    return NGX_OK;
}


ngx_int_t
ngx_http_apisix_is_body_filter_by_lua_skipped(ngx_http_request_t *r)
{
    ngx_http_apisix_ctx_t          *ctx;

    ctx = ngx_http_apisix_get_module_ctx(r);
    if (ctx != NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "apisix body_filter_by_lua %p skipped: %d",
                       ctx, ctx->body_filter_by_lua_skipped);

        return ctx->body_filter_by_lua_skipped;
    }

    return 0;
}


int
ngx_http_apisix_set_gm_cert(ngx_http_request_t *r, void *cdata, char **err, ngx_flag_t type)
{
#ifndef TONGSUO_VERSION_NUMBER

    *err = "only Tongsuo supported";
    return NGX_ERROR;

#else
    int                i;
    X509              *x509 = NULL;
    ngx_ssl_conn_t    *ssl_conn;
    STACK_OF(X509)    *chain = cdata;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    if (sk_X509_num(chain) < 1) {
        *err = "invalid certificate chain";
        goto failed;
    }

    x509 = sk_X509_value(chain, 0);
    if (x509 == NULL) {
        *err = "sk_X509_value() failed";
        goto failed;
    }

    if (type == NGX_HTTP_APISIX_SSL_ENC) {
        if (SSL_use_enc_certificate(ssl_conn, x509) == 0) {
            *err = "SSL_use_enc_certificate() failed";
            goto failed;
        }
    } else {
        if (SSL_use_sign_certificate(ssl_conn, x509) == 0) {
            *err = "SSL_use_sign_certificate() failed";
            goto failed;
        }
    }

    x509 = NULL;

    /* read rest of the chain */

    for (i = 1; i < sk_X509_num(chain); i++) {

        x509 = sk_X509_value(chain, i);
        if (x509 == NULL) {
            *err = "sk_X509_value() failed";
            goto failed;
        }

        if (SSL_add1_chain_cert(ssl_conn, x509) == 0) {
            *err = "SSL_add1_chain_cert() failed";
            goto failed;
        }
    }

    *err = NULL;
    return NGX_OK;

failed:

    ERR_clear_error();

    return NGX_ERROR;

#endif
}


int
ngx_http_apisix_set_gm_priv_key(ngx_http_request_t *r,
    void *cdata, char **err, ngx_flag_t type)
{
#ifndef TONGSUO_VERSION_NUMBER

    *err = "only Tongsuo supported";
    return NGX_ERROR;

#else

    EVP_PKEY          *pkey = NULL;
    ngx_ssl_conn_t    *ssl_conn;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    pkey = cdata;
    if (pkey == NULL) {
        *err = "invalid private key failed";
        goto failed;
    }

    if (type == NGX_HTTP_APISIX_SSL_ENC) {
        if (SSL_use_enc_PrivateKey(ssl_conn, pkey) == 0) {
            *err = "SSL_use_enc_PrivateKey() failed";
            goto failed;
        }
    } else {
        if (SSL_use_sign_PrivateKey(ssl_conn, pkey) == 0) {
            *err = "SSL_use_sign_PrivateKey() failed";
            goto failed;
        }
    }

    return NGX_OK;

failed:

    ERR_clear_error();

    return NGX_ERROR;

#endif
}
