local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local get_phase = ngx.get_phase
local C = ffi.C
local NGX_ERROR = ngx.ERROR
local NGX_OK = ngx.OK


base.allows_subsystem("http")


ffi.cdef[[
typedef intptr_t        ngx_int_t;
ngx_int_t ngx_http_apisix_upstream_set_cert_and_key(ngx_http_request_t *r, void *cert, void *key);
ngx_int_t ngx_http_apisix_upstream_set_ssl_trusted_store(ngx_http_request_t *r, void *store);
]]
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


return _M
