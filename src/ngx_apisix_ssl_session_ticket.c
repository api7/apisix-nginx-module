#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_apisix_ssl_session_ticket.h"


#if (NGX_APISIX_SSL_SESSION_TICKET)

/*
 * The hooks in nginx were reviewed against these releases only. Before adding
 * one, check again that both SSL merge call sites bind the mark right before
 * ngx_ssl_session_ticket_keys(), that ngx_apisix_ssl_session_ticket_register()
 * still runs before its return for a context without a shared session cache,
 * and run the takeover tests of both subsystems.
 */
#if (nginx_version != 1031001)
#error "the apisix session ticket takeover is not verified for this nginx"
#endif


typedef struct {
    u_char                                  name[16];
    u_char                                  hmac_key[32];
    u_char                                  aes_key[32];
} ngx_apisix_ssl_session_ticket_key_t;


typedef struct {
    ngx_uint_t                              nelts;
    ngx_apisix_ssl_session_ticket_key_t    *elts;
} ngx_apisix_ssl_session_ticket_keys_t;


struct ngx_apisix_ssl_session_ticket_s {
    SSL_CTX                                *ssl_ctx;
    /*
     * The complete ordered set: the first key encrypts, every key decrypts.
     * Replaced as a whole, never edited in place, NULL when there is none.
     */
    ngx_apisix_ssl_session_ticket_keys_t   *keys;
    ngx_uint_t                              id;
    ngx_uint_t                              generation;
    ngx_str_t                               location;
    unsigned                                registered:1;
};


static ngx_uint_t ngx_apisix_ssl_session_ticket_verified(
    ngx_apisix_ssl_session_ticket_t *t);
static void ngx_apisix_ssl_session_ticket_free_keys(
    ngx_apisix_ssl_session_ticket_t *t);
static void ngx_apisix_ssl_session_ticket_cleanup(void *data);
#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB
static int ngx_apisix_ssl_session_ticket_callback(ngx_ssl_conn_t *ssl_conn,
    unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
    HMAC_CTX *hctx, int enc);
#endif


/* the SSL_CTX ex_data that marks a context, allocated by the first mark */
static int  ngx_apisix_ssl_session_ticket_index = -1;


#if (NGX_DEBUG)

/*
 * Test only: the failures below cannot be caused from outside, so the tests
 * provoke them through the environment of the process that reads the
 * configuration. Not compiled in a build without --with-debug.
 */

#define NGX_APISIX_SSL_SESSION_TICKET_TEST_REGISTER                           \
    "APISIX_TEST_SSL_SESSION_TICKET_REGISTER_FAIL"

/*
 * the hex names of the keys the callback fails with, as if the crypto
 * library failed: [0] when encrypting, [1] when decrypting
 */
static char  *ngx_apisix_ssl_session_ticket_test_env[2] = {
    "APISIX_TEST_SSL_SESSION_TICKET_FAIL_ENCRYPT",
    "APISIX_TEST_SSL_SESSION_TICKET_FAIL_DECRYPT"
};

static u_char      ngx_apisix_ssl_session_ticket_test_key[2][32];
static ngx_uint_t  ngx_apisix_ssl_session_ticket_test_key_set[2];


static void
ngx_apisix_ssl_session_ticket_test_init(void)
{
    u_char      *p;
    ngx_uint_t   i;

    for (i = 0; i < 2; i++) {
        p = (u_char *) getenv(ngx_apisix_ssl_session_ticket_test_env[i]);

        if (p != NULL && ngx_strlen(p) == 32) {
            ngx_memcpy(ngx_apisix_ssl_session_ticket_test_key[i], p, 32);
            ngx_apisix_ssl_session_ticket_test_key_set[i] = 1;
        }
    }
}


static ngx_uint_t
ngx_apisix_ssl_session_ticket_test_fail(ngx_connection_t *c, int enc,
    ngx_apisix_ssl_session_ticket_key_t *key)
{
    u_char      hex[32];
    ngx_uint_t  i;

    i = (enc == 1) ? 0 : 1;

    if (!ngx_apisix_ssl_session_ticket_test_key_set[i]) {
        return 0;
    }

    ngx_hex_dump(hex, key->name, 16);

    if (ngx_memcmp(hex, ngx_apisix_ssl_session_ticket_test_key[i], 32) != 0) {
        return 0;
    }

    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                  "apisix ssl ticket %s with key \"%*s\" failed for the test",
                  (enc == 1) ? "encrypt" : "decrypt", (size_t) 32, hex);

    return 1;
}

#endif


ngx_int_t
ngx_apisix_ssl_session_ticket_bind(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *contexts, ngx_str_t *location)
{
    ngx_pool_cleanup_t               *cln;
    ngx_apisix_ssl_session_ticket_t  *t, **tp;

    if (ngx_apisix_ssl_session_ticket_index == -1) {
        ngx_apisix_ssl_session_ticket_index =
                           SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);

        if (ngx_apisix_ssl_session_ticket_index == -1) {
            ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                          "SSL_CTX_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    t = ngx_pcalloc(cf->pool, sizeof(ngx_apisix_ssl_session_ticket_t));
    if (t == NULL) {
        return NGX_ERROR;
    }

    t->ssl_ctx = ssl->ctx;
    t->id = contexts->nelts + 1;
    t->location = *location;

    /* the generation being configured, init_module() commits it */
    t->generation = ngx_apisix_get_generation() + 1;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_apisix_ssl_session_ticket_cleanup;
    cln->data = t;

    if (SSL_CTX_set_ex_data(ssl->ctx, ngx_apisix_ssl_session_ticket_index, t)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NGX_ERROR;
    }

    /*
     * Whatever ssl_session_tickets says, a marked context starts without
     * stateless tickets: they are only turned on once a complete set of keys
     * is installed, and stay off if the registration below fails, rather
     * than falling back to the keys OpenSSL makes up per context.
     */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TICKET);

    tp = ngx_array_push(contexts);
    if (tp == NULL) {
        return NGX_ERROR;
    }

    *tp = t;

    return NGX_OK;
}


ngx_int_t
ngx_apisix_ssl_session_ticket_register(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *paths)
{
    ngx_apisix_ssl_session_ticket_t  *t;

    if (ngx_apisix_ssl_session_ticket_index == -1) {
        return NGX_DECLINED;
    }

    t = SSL_CTX_get_ex_data(ssl->ctx, ngx_apisix_ssl_session_ticket_index);

    if (t == NULL) {
        /* not marked, nginx keeps its own keys */
        return NGX_DECLINED;
    }

    if (paths != NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "\"ssl_session_ticket_key\" cannot be used in a server "
                      "with \"apisix_ssl_session_ticket_takeover\" on, "
                      "in %V", &t->location);
        return NGX_ERROR;
    }

#if (NGX_DEBUG)

    ngx_apisix_ssl_session_ticket_test_init();

    if (getenv(NGX_APISIX_SSL_SESSION_TICKET_TEST_REGISTER) != NULL) {
        goto failed;
    }

#endif

#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

    /*
     * OpenSSL has no getter for the callback: the record of the successful
     * registration on this very context is what tells it is in place
     */

    if (SSL_CTX_set_tlsext_ticket_key_cb(ssl->ctx,
                                         ngx_apisix_ssl_session_ticket_callback)
        != 0)
    {
        t->registered = 1;
        return NGX_OK;
    }

#endif

#if (NGX_DEBUG)
failed:
#endif

    ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                  "failed to register the session ticket key callback, "
                  "session tickets stay off for the server in %V",
                  &t->location);

    return NGX_OK;
}


static ngx_uint_t
ngx_apisix_ssl_session_ticket_verified(ngx_apisix_ssl_session_ticket_t *t)
{
    return t->registered
           && SSL_CTX_get_ex_data(t->ssl_ctx,
                                  ngx_apisix_ssl_session_ticket_index) == t
           && t->generation == ngx_apisix_get_generation();
}


void
ngx_apisix_ssl_session_ticket_info(ngx_apisix_ssl_session_ticket_t *t,
    ngx_apisix_ssl_session_ticket_info_t *info)
{
    info->id = t->id;
    info->registered = ngx_apisix_ssl_session_ticket_verified(t);
    info->tickets = !(SSL_CTX_get_options(t->ssl_ctx) & SSL_OP_NO_TICKET);
    info->nkeys = t->keys ? t->keys->nelts : 0;
    info->generation = t->generation;
    info->conf = t->location.data;
    info->conf_len = t->location.len;
}


ngx_int_t
ngx_apisix_ssl_session_ticket_set_keys(ngx_apisix_ssl_session_ticket_t *t,
    const u_char *data, size_t len, char **err)
{
    ngx_uint_t                             i, j, n;
    const u_char                          *p, *q;
    ngx_apisix_ssl_session_ticket_key_t   *key;
    ngx_apisix_ssl_session_ticket_keys_t  *keys, *old;

    if (!ngx_apisix_ssl_session_ticket_verified(t)) {
        *err = "not_registered";
        return NGX_DECLINED;
    }

    if (len == 0 || len % NGX_APISIX_SSL_SESSION_TICKET_KEY_SIZE != 0) {
        *err = "invalid_keys: not a non-empty list of 80 byte keys";
        return NGX_ERROR;
    }

    n = len / NGX_APISIX_SSL_SESSION_TICKET_KEY_SIZE;

    if (n > NGX_APISIX_SSL_SESSION_TICKET_MAX_KEYS) {
        *err = "invalid_keys: too many keys";
        return NGX_ERROR;
    }

    /* the name of a ticket picks the key to decrypt it with */

    for (i = 1; i < n; i++) {
        p = data + i * NGX_APISIX_SSL_SESSION_TICKET_KEY_SIZE;

        for (j = 0; j < i; j++) {
            q = data + j * NGX_APISIX_SSL_SESSION_TICKET_KEY_SIZE;

            if (ngx_memcmp(p, q, 16) == 0) {
                *err = "invalid_keys: duplicate key name";
                return NGX_ERROR;
            }
        }
    }

    keys = ngx_alloc(sizeof(ngx_apisix_ssl_session_ticket_keys_t)
                     + n * sizeof(ngx_apisix_ssl_session_ticket_key_t),
                     ngx_cycle->log);
    if (keys == NULL) {
        *err = "failed: no memory";
        return NGX_ERROR;
    }

    keys->nelts = n;
    keys->elts = (ngx_apisix_ssl_session_ticket_key_t *) (keys + 1);

    for (i = 0; i < n; i++) {
        key = &keys->elts[i];
        p = data + i * NGX_APISIX_SSL_SESSION_TICKET_KEY_SIZE;

        ngx_memcpy(key->name, p, 16);
        ngx_memcpy(key->hmac_key, p + 16, 32);
        ngx_memcpy(key->aes_key, p + 48, 32);
    }

    /*
     * The callback runs in this same thread, so it only ever sees the old
     * complete set or the new one: never an empty or a partial one, and
     * never a slot that was not filled.
     */

    old = t->keys;
    t->keys = keys;

    if (old != NULL) {
        ngx_explicit_memzero(old->elts, old->nelts
                             * sizeof(ngx_apisix_ssl_session_ticket_key_t));
        ngx_free(old);
    }

    return NGX_OK;
}


ngx_int_t
ngx_apisix_ssl_session_ticket_revoke_keys(ngx_apisix_ssl_session_ticket_t *t)
{
    /* stop tickets before the keys they are encrypted with go away */
    SSL_CTX_set_options(t->ssl_ctx, SSL_OP_NO_TICKET);

    ngx_apisix_ssl_session_ticket_free_keys(t);

    return NGX_OK;
}


ngx_int_t
ngx_apisix_ssl_session_ticket_set_tickets(ngx_apisix_ssl_session_ticket_t *t,
    int on, char **err)
{
    if (!on) {
        SSL_CTX_set_options(t->ssl_ctx, SSL_OP_NO_TICKET);
        return NGX_OK;
    }

    if (!ngx_apisix_ssl_session_ticket_verified(t)) {
        *err = "not_registered";
        return NGX_DECLINED;
    }

    /* stateless tickets only go on with a complete set to encrypt them */

    if (t->keys == NULL) {
        *err = "no_keys";
        return NGX_DECLINED;
    }

    SSL_CTX_clear_options(t->ssl_ctx, SSL_OP_NO_TICKET);

    return NGX_OK;
}


ngx_int_t
ngx_apisix_ssl_session_ticket_connection(void *ssl_conn, int sync,
    ngx_apisix_ssl_session_ticket_conn_t *conn, char **err)
{
    SSL_CTX                          *ssl_ctx;
    ngx_connection_t                 *c;
    ngx_apisix_ssl_session_ticket_t  *t;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    if (c == NULL || c->ssl == NULL) {
        *err = "no_ssl";
        return NGX_ERROR;
    }

    /*
     * OpenSSL calls the ticket callback of the context the handshake started
     * with, even once the server name has switched the connection to another
     */

    ssl_ctx = c->ssl->session_ctx;

    t = NULL;

    if (ngx_apisix_ssl_session_ticket_index != -1) {
        t = SSL_CTX_get_ex_data(ssl_ctx, ngx_apisix_ssl_session_ticket_index);
    }

    if (t == NULL) {
        *err = "not_marked";
        return NGX_DECLINED;
    }

    if (sync) {

        /*
         * SSL_new() copied the options of the context when the connection
         * was accepted, the context may have changed since
         */

        if ((SSL_CTX_get_options(ssl_ctx) & SSL_OP_NO_TICKET)
            || t->keys == NULL
            || !ngx_apisix_ssl_session_ticket_verified(t))
        {
            SSL_set_options(c->ssl->connection, SSL_OP_NO_TICKET);

        } else {
            SSL_clear_options(c->ssl->connection, SSL_OP_NO_TICKET);
        }
    }

    conn->id = t->id;
    conn->tickets = !(SSL_get_options(c->ssl->connection) & SSL_OP_NO_TICKET);

    return NGX_OK;
}


#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

static int
ngx_apisix_ssl_session_ticket_callback(ngx_ssl_conn_t *ssl_conn,
    unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
    HMAC_CTX *hctx, int enc)
{
    SSL_CTX                               *ssl_ctx;
    ngx_uint_t                             i;
    ngx_connection_t                      *c;
    const EVP_MD                          *digest;
    const EVP_CIPHER                      *cipher;
    ngx_apisix_ssl_session_ticket_t       *t;
    ngx_apisix_ssl_session_ticket_key_t   *key;
    ngx_apisix_ssl_session_ticket_keys_t  *keys;

    c = ngx_ssl_get_connection(ssl_conn);
    ssl_ctx = c->ssl->session_ctx;

    t = SSL_CTX_get_ex_data(ssl_ctx, ngx_apisix_ssl_session_ticket_index);

    /*
     * The connection copied the options of the context when it was created,
     * and the context may have been turned off since: its keys must not be
     * used then, even though OpenSSL still asks for them. Returning 0 makes
     * OpenSSL decline the ticket, which costs a full handshake, or send none
     * (an empty one in TLSv1.2): never a ticket under keys of its own.
     */

    if (t == NULL
        || !t->registered
        || t->keys == NULL
        || (SSL_CTX_get_options(ssl_ctx) & SSL_OP_NO_TICKET))
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "apisix ssl ticket %s refused, tickets are off",
                       enc == 1 ? "encrypt" : "decrypt");
        return 0;
    }

    keys = t->keys;
    key = keys->elts;

#ifdef OPENSSL_NO_SHA256
    digest = EVP_sha1();
#else
    digest = EVP_sha256();
#endif

    cipher = EVP_aes_256_cbc();

    if (enc == 1) {
        /* encrypt session ticket */

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "apisix ssl ticket encrypt, key: \"%*xs\" (%s session)",
                       (size_t) 16, key[0].name,
                       SSL_session_reused(ssl_conn) ? "reused" : "new");

#if (NGX_DEBUG)
        if (ngx_apisix_ssl_session_ticket_test_fail(c, enc, &key[0])) {
            return -1;
        }
#endif

        if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "RAND_bytes() failed");
            return -1;
        }

        if (EVP_EncryptInit_ex(ectx, cipher, NULL, key[0].aes_key, iv) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "EVP_EncryptInit_ex() failed");
            return -1;
        }

        if (HMAC_Init_ex(hctx, key[0].hmac_key, 32, digest, NULL) != 1) {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
            return -1;
        }

        ngx_memcpy(name, key[0].name, 16);

        return 1;
    }

    /* decrypt session ticket */

    for (i = 0; i < keys->nelts; i++) {
        if (ngx_memcmp(name, key[i].name, 16) == 0) {
            goto found;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "apisix ssl ticket decrypt, key: \"%*xs\" not found",
                   (size_t) 16, name);

    return 0;

found:

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "apisix ssl ticket decrypt, key: \"%*xs\"%s",
                   (size_t) 16, key[i].name, (i == 0) ? " (default)" : "");

#if (NGX_DEBUG)
    if (ngx_apisix_ssl_session_ticket_test_fail(c, enc, &key[i])) {
        return -1;
    }
#endif

    if (HMAC_Init_ex(hctx, key[i].hmac_key, 32, digest, NULL) != 1) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
        return -1;
    }

    if (EVP_DecryptInit_ex(ectx, cipher, NULL, key[i].aes_key, iv) != 1) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "EVP_DecryptInit_ex() failed");
        return -1;
    }

    /* renew as nginx does: always in TLSv1.3, else for a non-default key */

#ifdef TLS1_3_VERSION
    if (SSL_version(ssl_conn) == TLS1_3_VERSION) {
        return 2;
    }
#endif

    if (i != 0) {
        return 2;
    }

    return 1;
}

#endif


static void
ngx_apisix_ssl_session_ticket_free_keys(ngx_apisix_ssl_session_ticket_t *t)
{
    ngx_apisix_ssl_session_ticket_keys_t  *keys;

    keys = t->keys;

    if (keys == NULL) {
        return;
    }

    t->keys = NULL;

    ngx_explicit_memzero(keys->elts, keys->nelts
                         * sizeof(ngx_apisix_ssl_session_ticket_key_t));
    ngx_free(keys);
}


static void
ngx_apisix_ssl_session_ticket_cleanup(void *data)
{
    ngx_apisix_ssl_session_ticket_t  *t = data;

    ngx_apisix_ssl_session_ticket_free_keys(t);
}


#else


/* without the patch nothing is ever marked, and Lua never gets a context */

void
ngx_apisix_ssl_session_ticket_info(ngx_apisix_ssl_session_ticket_t *t,
    ngx_apisix_ssl_session_ticket_info_t *info)
{
    ngx_memzero(info, sizeof(ngx_apisix_ssl_session_ticket_info_t));
}


ngx_int_t
ngx_apisix_ssl_session_ticket_set_keys(ngx_apisix_ssl_session_ticket_t *t,
    const u_char *data, size_t len, char **err)
{
    *err = "not_supported";
    return NGX_DECLINED;
}


ngx_int_t
ngx_apisix_ssl_session_ticket_revoke_keys(ngx_apisix_ssl_session_ticket_t *t)
{
    return NGX_DECLINED;
}


ngx_int_t
ngx_apisix_ssl_session_ticket_set_tickets(ngx_apisix_ssl_session_ticket_t *t,
    int on, char **err)
{
    *err = "not_supported";
    return NGX_DECLINED;
}


ngx_int_t
ngx_apisix_ssl_session_ticket_connection(void *ssl_conn, int sync,
    ngx_apisix_ssl_session_ticket_conn_t *conn, char **err)
{
    *err = "not_supported";
    return NGX_DECLINED;
}


#endif


char *
ngx_apisix_ssl_session_ticket_takeover(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf, ngx_str_t *location)
{
    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    location->data = ngx_pnalloc(cf->pool, cf->conf_file->file.name.len
                                           + 1 + NGX_INT_T_LEN);
    if (location->data == NULL) {
        return NGX_CONF_ERROR;
    }

    location->len = ngx_sprintf(location->data, "%V:%ui",
                                &cf->conf_file->file.name,
                                cf->conf_file->line)
                    - location->data;

#if !(NGX_APISIX_SSL_SESSION_TICKET)

    if (*(ngx_flag_t *) ((char *) conf + cmd->offset)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"%V\" has no effect, this nginx is built without "
                           "the session ticket takeover patch", &cmd->name);
    }

#endif

    return NGX_CONF_OK;
}
