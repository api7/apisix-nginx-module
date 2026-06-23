local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local NGX_ERROR = ngx.ERROR


base.allows_subsystem("stream")


ffi.cdef([[
typedef intptr_t        ngx_int_t;
ngx_int_t
ngx_stream_apisix_upstream_enable_tls(ngx_stream_lua_request_t *r);
ngx_int_t
ngx_stream_apisix_upstream_set_cert_and_key(ngx_stream_lua_request_t *r, void *cert, void *key);
]])
local _M = {}


function _M.set_tls()
    -- Unlike Kong, we choose to enable TLS instead of disabling it by Lua method.
    -- This way is more intuitive.
    -- The side effect is that we need to change Nginx to check `ssl_enable` flag instead.
    local r = get_request()
    local rc = C.ngx_stream_apisix_upstream_enable_tls(r)
    if rc == NGX_ERROR then
        return nil, "error while setting upstream tls"
    end

    return true
end


function _M.set_cert_and_key(cert, key)
    if not cert or not key then
        return nil, "both client certificate and private key should be given"
    end

    local r = get_request()
    local ret = C.ngx_stream_apisix_upstream_set_cert_and_key(r, cert, key)
    if ret == NGX_ERROR then
        return nil, "error while setting upstream client cert and key"
    end

    return true
end


return _M
