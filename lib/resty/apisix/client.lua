local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local NGX_ERROR = ngx.ERROR


base.allows_subsystem("http")


ffi.cdef([[
typedef intptr_t        ngx_int_t;
typedef uintptr_t       off_t;
ngx_int_t
ngx_http_apisix_client_set_max_body_size(ngx_http_request_t *r, off_t bytes);
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


return _M
