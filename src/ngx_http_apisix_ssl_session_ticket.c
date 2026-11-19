#include "ngx_http_apisix_ssl_session_ticket.h"

#define NGX_HTTP_APISIX_TICKET_MAX 256

#if (NGX_HTTP_SSL && NGX_HTTP_APISIX_SSL_SESSION_TICKET)

typedef struct {
    ngx_ssl_ticket_key_t    key;
    int64_t                 encrypt_from;
    int64_t                 encrypt_until;
    int64_t                 decrypt_until;
    uint32_t                lifetime;
} ngx_http_apisix_managed_ticket_t;

static int ngx_http_apisix_ticket_index = -1;
static ngx_http_apisix_managed_ticket_t
    ngx_http_apisix_tickets[NGX_HTTP_APISIX_TICKET_MAX];
static size_t ngx_http_apisix_ticket_count;

static ngx_int_t
ngx_http_apisix_ticket_current(int64_t now)
{
    size_t                              index;
    ngx_int_t                           selected;
    ngx_http_apisix_managed_ticket_t    *candidate, *current;

    selected = NGX_ERROR;
    for (index = 0; index < ngx_http_apisix_ticket_count; index++) {
        candidate = &ngx_http_apisix_tickets[index];
        if (candidate->decrypt_until == 0
            || now >= candidate->decrypt_until)
        {
            ngx_explicit_memzero(&candidate->key, sizeof(candidate->key));
            candidate->decrypt_until = 0;
            continue;
        }

        if (now < candidate->encrypt_from || now >= candidate->encrypt_until) {
            continue;
        }

        if (selected == NGX_ERROR) {
            selected = (ngx_int_t) index;
            continue;
        }

        current = &ngx_http_apisix_tickets[selected];
        if (candidate->encrypt_from > current->encrypt_from
            || (candidate->encrypt_from == current->encrypt_from
                && ngx_memcmp(candidate->key.name, current->key.name, 16) > 0))
        {
            selected = (ngx_int_t) index;
        }
    }

    return selected;
}

static ngx_int_t
ngx_http_apisix_ticket_worker(char **err)
{
    if ((ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        || ngx_http_apisix_ticket_index < 0)
    {
        *err = "session ticket API requires an initialized worker";
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_apisix_ssl_session_ticket_init(void)
{
    if (ngx_http_apisix_ticket_index == -1) {
        ngx_http_apisix_ticket_index = SSL_CTX_get_ex_new_index(0, NULL, NULL,
                                                             NULL, NULL);
    }

    return ngx_http_apisix_ticket_index == -1 ? NGX_ERROR : NGX_OK;
}

void
ngx_http_apisix_ssl_session_ticket_exit(ngx_cycle_t *cycle)
{
    ngx_explicit_memzero(ngx_http_apisix_tickets,
                        sizeof(ngx_http_apisix_tickets));
    ngx_http_apisix_ticket_count = 0;
}

int
ngx_http_apisix_ffi_ssl_session_ticket_supported(void)
{
    return 1;
}

int
ngx_http_apisix_ffi_ssl_session_ticket_set_keys(
    const ngx_http_apisix_ticket_key_t *keys, size_t count, size_t key_size,
    char **err)
{
    size_t                              index, previous;
    ngx_http_apisix_managed_ticket_t    *target;

    if (ngx_http_apisix_ticket_worker(err) != NGX_OK) {
        return NGX_ERROR;
    }

    if (key_size != sizeof(ngx_http_apisix_ticket_key_t)
        || count > NGX_HTTP_APISIX_TICKET_MAX || (count && keys == NULL))
    {
        *err = "invalid session ticket key array size";
        return NGX_ERROR;
    }

    for (index = 0; index < count; index++) {
        if (keys[index].encrypt_from < 0
            || keys[index].encrypt_from >= keys[index].encrypt_until
            || keys[index].encrypt_until >= keys[index].decrypt_until
            || keys[index].lifetime < 1 || keys[index].lifetime > 604800)
        {
            *err = "invalid session ticket time window or lifetime";
            return NGX_ERROR;
        }

        for (previous = 0; previous < index; previous++) {
            if (ngx_memcmp(keys[index].raw, keys[previous].raw, 16) == 0) {
                *err = "duplicate session ticket key name";
                return NGX_ERROR;
            }
        }
    }

    ngx_http_apisix_ssl_session_ticket_exit(NULL);
    for (index = 0; index < count; index++) {
        target = &ngx_http_apisix_tickets[index];
        target->key.size = 80;
        target->key.expire = 1;
        ngx_memcpy(target->key.name, keys[index].raw, 16);
        ngx_memcpy(target->key.hmac_key, keys[index].raw + 16, 32);
        ngx_memcpy(target->key.aes_key, keys[index].raw + 48, 32);
        target->encrypt_from = keys[index].encrypt_from;
        target->encrypt_until = keys[index].encrypt_until;
        target->decrypt_until = keys[index].decrypt_until;
        target->lifetime = keys[index].lifetime;
    }

    ngx_http_apisix_ticket_count = count;
    ngx_http_apisix_ticket_current((int64_t) time(NULL));
    return NGX_OK;
}

int
ngx_http_apisix_ffi_ssl_session_ticket_expire_keys(char **err)
{
    if (ngx_http_apisix_ticket_worker(err) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_apisix_ticket_current((int64_t) time(NULL));
    return NGX_OK;
}

int
ngx_http_apisix_ffi_ssl_session_ticket_client_hello(ngx_http_request_t *request,
    char **err)
{
    SSL_CTX                 *ssl_ctx;
    ngx_array_t             *keys;
    ngx_ssl_conn_t          *ssl_conn;
    ngx_ssl_ticket_key_t    *native_keys;
    ngx_int_t                selected;

    if (ngx_http_apisix_ticket_worker(err) != NGX_OK) {
        return NGX_ERROR;
    }

    if (request == NULL || request->connection == NULL
        || request->connection->ssl == NULL
        || request->connection->ssl->connection == NULL)
    {
        *err = "no TLS connection";
        return NGX_ERROR;
    }

    ssl_conn = request->connection->ssl->connection;
    ssl_ctx = request->connection->ssl->session_ctx;
    if (SSL_CTX_get_ex_data(ssl_ctx, ngx_http_apisix_ticket_index) == NULL) {
        keys = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ticket_keys_index);
        if (SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_session_cache_index) == NULL
            || keys == NULL || keys->nelts != 3)
        {
            *err = "managed tickets require a shared session cache";
            return NGX_ERROR;
        }

        native_keys = keys->elts;
        if (!native_keys[0].shared
            || (SSL_CTX_get_options(ssl_ctx) & SSL_OP_NO_TICKET))
        {
            *err = "managed tickets require tickets on without key files";
            return NGX_ERROR;
        }

        if (SSL_CTX_get_max_early_data(ssl_ctx) != 0) {
            *err = "managed tickets require early data off";
            return NGX_ERROR;
        }

        if (SSL_CTX_set_ex_data(ssl_ctx, ngx_http_apisix_ticket_index,
                               (void *) 1) != 1)
        {
            *err = "failed to bind managed ticket context";
            return NGX_ERROR;
        }
    }

    selected = ngx_http_apisix_ticket_current((int64_t) time(NULL));
    if (selected != NGX_ERROR) {
        SSL_CTX_set_timeout(ssl_ctx,
                           (long) ngx_http_apisix_tickets[selected].lifetime);
        SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TICKET);
        SSL_clear_options(ssl_conn, SSL_OP_NO_TICKET);

    } else {
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);
        SSL_set_options(ssl_conn, SSL_OP_NO_TICKET);
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_apisix_ssl_session_ticket_key(ngx_ssl_conn_t *ssl_conn, u_char *name,
    int enc, ngx_ssl_ticket_key_t **key, int *renew)
{
    SSL_CTX             *ssl_ctx;
    int64_t              now;
    size_t               index;
    ngx_int_t            selected;
    ngx_connection_t    *connection;

    connection = ngx_ssl_get_connection(ssl_conn);
    ssl_ctx = connection->ssl->session_ctx;
    if (ngx_http_apisix_ticket_index == -1
        || SSL_CTX_get_ex_data(ssl_ctx, ngx_http_apisix_ticket_index) == NULL)
    {
        return NGX_DECLINED;
    }

    now = (int64_t) time(NULL);
    selected = ngx_http_apisix_ticket_current(now);
    if (selected == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (enc == 1) {
        *key = &ngx_http_apisix_tickets[selected].key;
        return NGX_OK;
    }

    for (index = 0; index < ngx_http_apisix_ticket_count; index++) {
        if (ngx_http_apisix_tickets[index].decrypt_until != 0
            && now < ngx_http_apisix_tickets[index].decrypt_until
            && ngx_memcmp(name, ngx_http_apisix_tickets[index].key.name, 16) == 0)
        {
            *key = &ngx_http_apisix_tickets[index].key;
            *renew = index != (size_t) selected;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

#else

ngx_int_t
ngx_http_apisix_ssl_session_ticket_init(void)
{
    return NGX_OK;
}

void
ngx_http_apisix_ssl_session_ticket_exit(ngx_cycle_t *cycle)
{
}

int
ngx_http_apisix_ffi_ssl_session_ticket_supported(void)
{
    return 0;
}

int
ngx_http_apisix_ffi_ssl_session_ticket_set_keys(
    const ngx_http_apisix_ticket_key_t *keys, size_t count, size_t key_size,
    char **err)
{
    *err = "native session ticket hook unavailable in this build";
    return NGX_ERROR;
}

int
ngx_http_apisix_ffi_ssl_session_ticket_expire_keys(char **err)
{
    *err = "native session ticket hook unavailable in this build";
    return NGX_ERROR;
}

int
ngx_http_apisix_ffi_ssl_session_ticket_client_hello(ngx_http_request_t *request,
    char **err)
{
    *err = "native session ticket hook unavailable in this build";
    return NGX_ERROR;
}

#endif
