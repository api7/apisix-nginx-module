local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local NGX_ERROR = ngx.ERROR


base.allows_subsystem("http")


ffi.cdef([[
typedef intptr_t        ngx_int_t;
ngx_int_t
ngx_http_apisix_upstream_set_cert_and_key(ngx_http_request_t *r, void *cert, void *key);
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


return _M
