local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local get_phase = ngx.get_phase
local C = ffi.C
local NGX_ERROR = ngx.ERROR
local NGX_OK = ngx.OK
local type = type


base.allows_subsystem("http")


ffi.cdef([[
typedef intptr_t        ngx_int_t;
ngx_int_t ngx_http_apisix_upstream_set_cert_and_key(ngx_http_request_t *r, void *cert, void *key);
ngx_int_t ngx_http_apisix_upstream_set_ssl_trusted_store(ngx_http_request_t *r, void *store);
int ngx_http_apisix_upstream_set_ssl_verify(ngx_http_request_t *r, int verify);

ngx_int_t ngx_http_apisix_set_upstream_pass_trailers(ngx_http_request_t *r, int on);

ngx_int_t ngx_http_apisix_push_upstream_state(ngx_http_request_t *r,
    const unsigned char *addr, size_t addr_len, ngx_int_t status,
    ngx_int_t connect_time_ms, ngx_int_t header_time_ms);
ngx_int_t ngx_http_apisix_update_upstream_state(ngx_http_request_t *r,
    ngx_int_t response_time_ms, intptr_t response_length);
]])
local _M = {}


function _M.set_cert_and_key(cert, key)
    if not cert or not key then
        return nil, "both client certificate and private key should be given"
    end

    local r = get_request()
    local ret = C.ngx_http_apisix_upstream_set_cert_and_key(r, cert, key)
    if ret == NGX_ERROR then
        return nil, "error while setting upstream client cert and key"
    end

    return true
end

local set_ssl_trusted_store
do
    local ALLOWED_PHASES = {
        ['rewrite'] = true,
        ['balancer'] = true,
        ['access'] = true,
        ['preread'] = true,
    }

    local openssl_x509_store = require "resty.openssl.x509.store"
    function set_ssl_trusted_store(store)
        if not ALLOWED_PHASES[get_phase()] then
            error("API disabled in the current context", 2)
        end

        if not openssl_x509_store.istype(store) then
            error("store expects a resty.openssl.x509.store" ..
                " object but get " .. type(store), 2)
        end

        local r = get_request()

        local ret = C.ngx_http_apisix_upstream_set_ssl_trusted_store(
            r, store.ctx)
        if ret == NGX_OK then
            return true
        end

        if ret == NGX_ERROR then
            return nil, "error while setting upstream trusted store"
        end

        error("unknown return code: " .. tostring(ret))
    end
end
_M.set_ssl_trusted_store = set_ssl_trusted_store


local set_ssl_verify
do
    local ALLOWED_PHASES = {
        ['rewrite'] = true,
        ['balancer'] = true,
        ['access'] = true,
        ['preread'] = true,
    }
    function set_ssl_verify(verify)
        if not ALLOWED_PHASES[get_phase()] then
            error("API disabled in the current context", 2)
        end

        if type(verify) ~= 'boolean' then
            error("verify expects a boolean but found " .. type(verify), 2)
        end

        local r = get_request()

        local ret = C.ngx_http_apisix_upstream_set_ssl_verify(
            r, verify)
        if ret == NGX_OK then
            return true
        end

        if ret == NGX_ERROR then
            return nil, "error while setting upstream ssl verify mode"
        end

        error("unknown return code: " .. tostring(ret))
    end
end
_M.set_ssl_verify = set_ssl_verify


function _M.set_pass_trailers(on)
    if type(on) ~= 'boolean' then
        return nil, "on expects a boolean but found " .. type(on)
    end

    local r = get_request()
    local ret = C.ngx_http_apisix_set_upstream_pass_trailers(r, on and 1 or 0)
    if ret == NGX_ERROR then
        return nil, "error while setting upstream pass_trailers"
    end

    return true
end


function _M.push_upstream_state(opts)
    if type(opts) ~= "table" then
        return nil, "opts must be a table"
    end

    local r = get_request()
    if not r then
        return nil, "no request found"
    end

    local addr = opts.addr
    if addr ~= nil and type(addr) ~= "string" then
        return nil, "addr must be a string"
    end
    local addr_len = addr and #addr or 0
    local ret = C.ngx_http_apisix_push_upstream_state(
        r,
        addr, addr_len,
        opts.status or 0,
        opts.connect_time or -1,
        opts.header_time or -1)
    if ret == NGX_ERROR then
        return nil, "error while pushing upstream state"
    end

    return true
end


function _M.update_upstream_state(opts)
    if type(opts) ~= "table" then
        return nil, "opts must be a table"
    end

    local r = get_request()
    if not r then
        return nil, "no request found"
    end

    local ret = C.ngx_http_apisix_update_upstream_state(
        r,
        opts.response_time or -1,
        opts.response_length or -1)
    if ret == NGX_ERROR then
        return nil, "error while updating upstream state"
    end

    return true
end


return _M
