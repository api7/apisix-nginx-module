local ffi = require("ffi")
local base = require("resty.core.base")
local C = ffi.C
local get_request = base.get_request

base.allows_subsystem("http")

ffi.cdef[[
typedef struct {
    unsigned char raw[80];
    int64_t encrypt_from;
    int64_t encrypt_until;
    int64_t decrypt_until;
    uint32_t lifetime;
} ngx_http_apisix_ticket_key_t;
int ngx_http_apisix_ffi_ssl_session_ticket_supported(void);
int ngx_http_apisix_ffi_ssl_session_ticket_set_keys(
    const ngx_http_apisix_ticket_key_t *keys, size_t count, size_t key_size,
    char **err);
int ngx_http_apisix_ffi_ssl_session_ticket_expire_keys(char **err);
int ngx_http_apisix_ffi_ssl_session_ticket_client_hello(void *request, char **err);
]]

local _M = {}
local key_size = ffi.sizeof("ngx_http_apisix_ticket_key_t")
local max_timestamp = 9007199254740991

local function integer(value, minimum, maximum)
    return type(value) == "number" and value >= minimum and value <= maximum
        and value == math.floor(value)
end

function _M.is_supported()
    return C.ngx_http_apisix_ffi_ssl_session_ticket_supported() == 1
end

function _M.set_keys(keys)
    if type(keys) ~= "table" then
        return nil, "expected a dense session ticket key array"
    end

    local count = 0
    for position in pairs(keys) do
        count = count + 1
        if not integer(position, 1, 256) then
            return nil, "expected a dense session ticket key array of at most 256 keys"
        end
    end

    for position = 1, count do
        local key = keys[position]
        if type(key) ~= "table" or type(key.key) ~= "string" or #key.key ~= 80 then
            return nil, "each session ticket key must contain 80 raw bytes"
        end
        if not integer(key.encrypt_from, 0, max_timestamp)
            or not integer(key.encrypt_until, 0, max_timestamp)
            or not integer(key.decrypt_until, 0, max_timestamp)
            or key.encrypt_from >= key.encrypt_until
            or key.encrypt_until >= key.decrypt_until
            or not integer(key.lifetime, 1, 604800) then
            return nil, "invalid session ticket time window or lifetime"
        end
    end

    local buffer = ffi.new("ngx_http_apisix_ticket_key_t[?]", math.max(1, count))
    for position = 1, count do
        local key = keys[position]
        ffi.copy(buffer[position - 1].raw, key.key, 80)
        buffer[position - 1].encrypt_from = key.encrypt_from
        buffer[position - 1].encrypt_until = key.encrypt_until
        buffer[position - 1].decrypt_until = key.decrypt_until
        buffer[position - 1].lifetime = key.lifetime
    end

    local err = base.get_errmsg_ptr()
    local result = C.ngx_http_apisix_ffi_ssl_session_ticket_set_keys(
        buffer, count, key_size, err)
    ffi.fill(buffer, math.max(1, count) * key_size, 0)
    if result ~= base.FFI_OK then
        return nil, ffi.string(err[0])
    end

    return true
end

function _M.expire_keys()
    local err = base.get_errmsg_ptr()
    if C.ngx_http_apisix_ffi_ssl_session_ticket_expire_keys(err) ~= base.FFI_OK then
        return nil, ffi.string(err[0])
    end
    return true
end

function _M.on_client_hello()
    if ngx.get_phase() ~= "ssl_client_hello" then
        return nil, "on_client_hello must run in ssl_client_hello_by_lua"
    end

    local err = base.get_errmsg_ptr()
    if C.ngx_http_apisix_ffi_ssl_session_ticket_client_hello(get_request(), err)
        ~= base.FFI_OK then
        return nil, ffi.string(err[0])
    end
    return true
end

return _M
