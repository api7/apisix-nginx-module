local ffi = require("ffi")
local base = require("resty.core.base")
local nkeys = require("table.nkeys")
local new_tab = base.new_tab
local get_request = base.get_request
local errmsg = base.get_errmsg_ptr()
local C = ffi.C
local ffi_str = ffi.string
local ffi_new = ffi.new
local tonumber = tonumber
local type = type
local concat = table.concat
local subsystem = ngx.config.subsystem


-- No allows_subsystem() guard: http and stream each have their own marked
-- servers, and this module only ever reaches those of the subsystem it is
-- loaded in.


ffi.cdef[[
typedef struct {
    uint32_t                id;
    uint32_t                registered;
    uint32_t                tickets;
    uint32_t                nkeys;
    uint64_t                generation;
    const unsigned char    *conf;
    size_t                  conf_len;
} ngx_apisix_ssl_session_ticket_info_t;

typedef struct {
    uint32_t                id;
    uint32_t                tickets;
} ngx_apisix_ssl_session_ticket_conn_t;

intptr_t ngx_http_apisix_ssl_session_ticket_count(void);
void *ngx_http_apisix_ssl_session_ticket_get(uintptr_t id);
intptr_t ngx_stream_apisix_ssl_session_ticket_count(void);
void *ngx_stream_apisix_ssl_session_ticket_get(uintptr_t id);

void ngx_apisix_ssl_session_ticket_info(void *t,
    ngx_apisix_ssl_session_ticket_info_t *info);
intptr_t ngx_apisix_ssl_session_ticket_set_keys(void *t,
    const unsigned char *keys, size_t len, char **err);
intptr_t ngx_apisix_ssl_session_ticket_revoke_keys(void *t);
intptr_t ngx_apisix_ssl_session_ticket_set_tickets(void *t, int on,
    char **err);
intptr_t ngx_apisix_ssl_session_ticket_connection(void *ssl_conn, int sync,
    ngx_apisix_ssl_session_ticket_conn_t *conn, char **err);
]]


-- must stay in sync with ngx_apisix_ssl_session_ticket.h
local KEY_SIZE = 80
local MAX_KEYS = 256

local NGX_OK = ngx.OK

local count_contexts
local get_context_ptr

-- the module is split over the http and the stream addons, so a build can
-- lack either half; resolve the symbols once rather than letting calls throw
local supported = pcall(function()
    if subsystem == "http" then
        count_contexts = C.ngx_http_apisix_ssl_session_ticket_count
        get_context_ptr = C.ngx_http_apisix_ssl_session_ticket_get

    elseif subsystem == "stream" then
        count_contexts = C.ngx_stream_apisix_ssl_session_ticket_count
        get_context_ptr = C.ngx_stream_apisix_ssl_session_ticket_get

    else
        error("unknown subsystem")
    end

    return C.ngx_apisix_ssl_session_ticket_connection
end)

-- the lua-resty-core of an older runtime has no getter for the SSL object
-- of the request, or no ngx.ssl for stream at all
local get_req_ssl_pointer
do
    local ok, ngx_ssl = pcall(require, "ngx.ssl")
    if ok then
        get_req_ssl_pointer = ngx_ssl.get_req_ssl_pointer
    end
end

local info = ffi_new("ngx_apisix_ssl_session_ticket_info_t")
local conn = ffi_new("ngx_apisix_ssl_session_ticket_conn_t")

local _M = {
    KEY_SIZE = KEY_SIZE,
    MAX_KEYS = MAX_KEYS,
}


local function get_context(id)
    if not supported then
        return nil, "not_supported"
    end

    if type(id) ~= "number" or id < 1 or id % 1 ~= 0 then
        return nil, "no_context"
    end

    local t = get_context_ptr(id)
    if t == nil then
        -- a build without the takeover has the symbols, and no context
        if tonumber(count_contexts()) < 0 then
            return nil, "not_supported"
        end

        return nil, "no_context"
    end

    return t
end


-- Returns the servers of the current subsystem marked with
-- apisix_ssl_session_ticket_takeover, as this worker has them:
--   { id = 1, registered = true, tickets = false, keys = 0,
--     generation = 3, conf = "/path/to/nginx.conf:42" }
-- id is the position of the server in the configuration and stays the same
-- for the life of the worker. A context with registered = false never takes
-- a key set nor turns tickets on.
-- Returns nil, "not_supported" when this nginx cannot take over the keys.
function _M.contexts()
    if not supported then
        return nil, "not_supported"
    end

    local n = tonumber(count_contexts())
    if n < 0 then
        return nil, "not_supported"
    end

    local res = new_tab(n, 0)

    for id = 1, n do
        C.ngx_apisix_ssl_session_ticket_info(get_context_ptr(id), info)

        res[id] = {
            id = id,
            registered = info.registered == 1,
            tickets = info.tickets == 1,
            keys = tonumber(info.nkeys),
            generation = tonumber(info.generation),
            conf = ffi_str(info.conf, info.conf_len),
        }
    end

    return res
end


-- Installs the complete ordered set of keys of a context, replacing the
-- previous one as a whole: the first key encrypts new tickets, every key
-- decrypts. Each key is 80 raw bytes in the nginx layout,
-- name(16) | HMAC(32) | AES-256(32). Does not turn tickets on.
function _M.set_keys(id, keys)
    local t, err = get_context(id)
    if not t then
        return nil, err
    end

    if type(keys) ~= "table" or nkeys(keys) ~= #keys or #keys == 0 then
        return nil, "invalid_keys: not a non-empty array of keys"
    end

    if #keys > MAX_KEYS then
        return nil, "invalid_keys: too many keys"
    end

    for i = 1, #keys do
        local key = keys[i]
        if type(key) ~= "string" or #key ~= KEY_SIZE then
            return nil, "invalid_keys: key " .. i .. " is not "
                        .. KEY_SIZE .. " bytes"
        end
    end

    local buf = concat(keys)

    local rc = C.ngx_apisix_ssl_session_ticket_set_keys(t, buf, #buf, errmsg)
    if rc ~= NGX_OK then
        return nil, ffi_str(errmsg[0])
    end

    return true
end


-- Turns tickets off, then drops the key set of a context.
function _M.revoke_keys(id)
    local t, err = get_context(id)
    if not t then
        return nil, err
    end

    C.ngx_apisix_ssl_session_ticket_revoke_keys(t)

    return true
end


-- Clears SSL_OP_NO_TICKET on a context, which takes an installed key set.
function _M.enable_tickets(id)
    local t, err = get_context(id)
    if not t then
        return nil, err
    end

    local rc = C.ngx_apisix_ssl_session_ticket_set_tickets(t, 1, errmsg)
    if rc ~= NGX_OK then
        return nil, ffi_str(errmsg[0])
    end

    return true
end


-- Sets SSL_OP_NO_TICKET on a context. The key set stays.
function _M.disable_tickets(id)
    local t, err = get_context(id)
    if not t then
        return nil, err
    end

    C.ngx_apisix_ssl_session_ticket_set_tickets(t, 0, errmsg)

    return true
end


local function connection(sync)
    if not supported or not get_req_ssl_pointer then
        return nil, "not_supported"
    end

    if not get_request() then
        return nil, "no_request"
    end

    local ssl_conn = get_req_ssl_pointer()
    if not ssl_conn then
        return nil, "no_ssl"
    end

    local rc = C.ngx_apisix_ssl_session_ticket_connection(ssl_conn,
                                                          sync and 1 or 0,
                                                          conn, errmsg)
    if rc ~= NGX_OK then
        return nil, ffi_str(errmsg[0])
    end

    return conn.tickets == 1, tonumber(conn.id)
end


-- Aligns SSL_OP_NO_TICKET on the current TLS connection with its context:
-- the connection copied the options of the context when it was accepted.
-- Meant for ssl_client_hello_by_lua*, before tickets are looked at.
-- Returns whether the connection may use tickets and the id of its context.
function _M.sync_connection()
    return connection(true)
end


-- Same as sync_connection(), without changing the connection.
function _M.connection_tickets()
    return connection(false)
end


return _M
