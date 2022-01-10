local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local NGX_ERROR = ngx.ERROR
local NGX_OK = ngx.OK


base.allows_subsystem("http")


ffi.cdef([[
typedef intptr_t        ngx_int_t;
typedef uintptr_t       off_t;
typedef unsigned char   u_char;

ngx_int_t
ngx_http_apisix_client_set_max_body_size(ngx_http_request_t *r, off_t bytes);

ngx_int_t
ngx_http_apisix_enable_mirror(ngx_http_request_t *r);

ngx_int_t
ngx_http_apisix_set_real_ip(ngx_http_request_t *r, const u_char *text, size_t len,
                            unsigned int port);

ngx_int_t
ngx_http_apisix_set_proxy_request_buffering(ngx_http_request_t *r, int on);
]])
local _M = {}


function _M.set_client_max_body_size(bytes)
    local r = get_request()
    local ret = C.ngx_http_apisix_client_set_max_body_size(r, tonumber(bytes))
    if ret == NGX_ERROR then
        return nil, "error while setting client max body size"
    end

    return true
end


function _M.enable_mirror()
    local r = get_request()
    local ret = C.ngx_http_apisix_enable_mirror(r)
    if ret == NGX_ERROR then
        return nil, "error while disaling mirror"
    end

    return true
end


function _M.set_real_ip(ip, port)
    -- APISIX will ensure the IP and port are valid
    if not port then
        port = 0
    end

    local r = get_request()
    local rc = C.ngx_http_apisix_set_real_ip(r, ip, #ip, port)
    if rc ~= NGX_OK then
        return nil, "error while setting real ip, rc: " .. tonumber(rc)
    end

    return true
end


function _M.set_proxy_request_buffering(on)
    local r = get_request()
    local ret = C.ngx_http_apisix_set_proxy_request_buffering(r, on and 1 or 0)
    if ret == NGX_ERROR then
        return nil, "error while setting proxy_request_buffering"
    end

    return true
end


return _M
