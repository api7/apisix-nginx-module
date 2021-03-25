#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_apisix_module.h"


static ngx_http_module_t ngx_http_apisix_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
};


ngx_module_t ngx_http_apisix_module = {
    NGX_MODULE_V1,
    &ngx_http_apisix_module_ctx,         /* module context */
    NULL,                                /* module directives */
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
