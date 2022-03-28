local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C


base.allows_subsystem("http")


ffi.cdef[[
typedef intptr_t ngx_int_t;
ngx_int_t
ngx_http_apisix_is_request_header_set(ngx_http_request_t *r);
void
ngx_http_apisix_clear_request_header(ngx_http_request_t *r);
]]


local _M = {}


function _M.is_request_header_set()
    local r = get_request()
    local rc = C.ngx_http_apisix_is_request_header_set(r)
    return rc == 1 and true or false
end


function _M.clear_request_header()
    local r = get_request()
    C.ngx_http_apisix_clear_request_header(r)
end


return _M
