local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local NGX_ERROR = ngx.ERROR


base.allows_subsystem("http")


ffi.cdef[[
typedef intptr_t ngx_int_t;
ngx_int_t
ngx_http_apisix_set_gzip(ngx_http_request_t *r, ngx_int_t num, size_t size,
    ngx_int_t level);
ngx_int_t
ngx_http_apisix_skip_header_filter_by_lua(ngx_http_request_t *r);
ngx_int_t
ngx_http_apisix_skip_body_filter_by_lua(ngx_http_request_t *r);
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


-- The skip_* methods must be called before any output is generated,
-- so the flag can take effect
function _M.skip_header_filter_by_lua()
    local r = get_request()
    local rc = C.ngx_http_apisix_skip_header_filter_by_lua(r)
    if rc == NGX_ERROR then
        return nil, "no memory"
    end
    return true
end


function _M.skip_body_filter_by_lua()
    local r = get_request()
    local rc = C.ngx_http_apisix_skip_body_filter_by_lua(r)
    if rc == NGX_ERROR then
        return nil, "no memory"
    end
    return true
end


return _M
