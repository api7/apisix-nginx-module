local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local NGX_ERROR = ngx.ERROR


base.allows_subsystem("http")


ffi.cdef[[
typedef intptr_t ngx_int_t;
typedef uintptr_t ngx_uint_t;
ngx_int_t
ngx_http_apisix_set_gzip(ngx_http_request_t *r, ngx_int_t num, size_t size,
    ngx_int_t level);
ngx_int_t 
ngx_http_apisix_set_proxy_ignore_headers(ngx_http_request_t *r, ngx_uint_t mask);
]]


local _M = {}


-- opts contains
-- * buffer_num
-- * buffer_size
-- * compress_level
function _M.set_gzip(opts)
    local r = get_request()
    local rc = C.ngx_http_apisix_set_gzip(r, opts.buffer_num, opts.buffer_size, opts.compress_level)
    if rc == NGX_ERROR then
        return nil, "no memory"
    end
    return true
end

-- opts contains
-- * mask
function _M.set_proxy_ignore_headers(opts)
    local r = get_request()
    local rc = C.ngx_http_apisix_set_proxy_ignore_headers(r, opts.mask)
    if rc == NGX_ERROR then
        return nil, "no memory"
    end
    return true
end

return _M
