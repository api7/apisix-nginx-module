#include <ngx_stream.h>
#include <ngx_stream_lua_api.h>
// #include "../ngx_stream_lua_common.h"
#include "ngx_stream_apisix_module.h"


#define NGX_STREAM_APISIX_SSL_ENC     1
#define NGX_STREAM_APISIX_SSL_SIGN    2


typedef struct {
    ngx_flag_t      enable_ntls;
} ngx_stream_apisix_main_conf_t;


typedef struct {
    unsigned             proxy_ssl_enabled:1;
} ngx_stream_apisix_ctx_t;


static void *ngx_stream_apisix_create_main_conf(ngx_conf_t *cf);


static ngx_stream_module_t ngx_stream_apisix_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    ngx_stream_apisix_create_main_conf,      /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
};


ngx_module_t ngx_stream_apisix_module = {
    NGX_MODULE_V1,
    &ngx_stream_apisix_module_ctx,       /* module context */
    NULL,                                /* module directives */
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
    ngx_stream_apisix_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_apisix_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


ngx_int_t
ngx_stream_apisix_upstream_enable_tls(ngx_stream_lua_request_t *r)
{
    ngx_stream_apisix_ctx_t       *ctx;

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_apisix_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_stream_apisix_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_lua_set_ctx(r, ctx, ngx_stream_apisix_module);
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



int
ngx_stream_apisix_set_gm_cert(ngx_stream_lua_request_t *r, void *cdata, char **err, ngx_flag_t type)
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

    if (type == NGX_STREAM_APISIX_SSL_ENC) {
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
ngx_stream_apisix_set_gm_priv_key(ngx_stream_lua_request_t *r,
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

    if (type == NGX_STREAM_APISIX_SSL_ENC) {
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


int
ngx_stream_apisix_enable_ntls(ngx_stream_lua_request_t *r, int enabled)
{
    ngx_stream_apisix_main_conf_t  *acf;

    acf = ngx_stream_get_module_main_conf(r->session, ngx_stream_apisix_module);
    acf->enable_ntls = enabled;
    return NGX_OK;
}


ngx_flag_t
ngx_stream_apisix_is_ntls_enabled(ngx_stream_session_t *s)
{
    ngx_stream_apisix_main_conf_t  *acf;

    acf = ngx_stream_get_module_main_conf(s, ngx_stream_apisix_module);
    return acf->enable_ntls;
}
