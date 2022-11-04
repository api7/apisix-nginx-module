local ffi = require("ffi")
local base = require("resty.core.base")
local errmsg = base.get_errmsg_ptr()
local get_request = base.get_request
local FFI_OK = base.FFI_OK
local C = ffi.C
local ffi_str = ffi.string


base.allows_subsystem("http")


ffi.cdef[[
    typedef intptr_t        ngx_flag_t;
    int ngx_http_apisix_set_gm_cert(void *r, void *cdata, char **err, ngx_flag_t type);
    int ngx_http_apisix_set_gm_priv_key(void *r, void *cdata, char **err, ngx_flag_t type);
    int ngx_http_apisix_enable_ntls(void *r, int enabled);
]]


local NGX_HTTP_APISIX_SSL_ENC = 1
local NGX_HTTP_APISIX_SSL_SIGN = 2
local _M = {}


function _M.set_gm_cert(enc_cert, sign_cert)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local rc = C.ngx_http_apisix_set_gm_cert(r, enc_cert, errmsg, NGX_HTTP_APISIX_SSL_ENC)
    if rc ~= FFI_OK then
        return nil, ffi_str(errmsg[0])
    end

    local rc = C.ngx_http_apisix_set_gm_cert(r, sign_cert, errmsg, NGX_HTTP_APISIX_SSL_SIGN)
    if rc ~= FFI_OK then
        return nil, ffi_str(errmsg[0])
    end

    return true
end


function _M.set_gm_priv_key(enc_pkey, sign_pkey)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local rc = C.ngx_http_apisix_set_gm_priv_key(r, enc_pkey, errmsg, NGX_HTTP_APISIX_SSL_ENC)
    if rc ~= FFI_OK then
        return nil, ffi_str(errmsg[0])
    end

    local rc = C.ngx_http_apisix_set_gm_priv_key(r, sign_pkey, errmsg, NGX_HTTP_APISIX_SSL_SIGN)
    if rc ~= FFI_OK then
        return nil, ffi_str(errmsg[0])
    end

    return true
end


function _M.enable_ntls()
    local r = get_request()
    if not r then
        error("no request found")
    end

    C.ngx_http_apisix_enable_ntls(r, 1)
end


function _M.disable_ntls()
    local r = get_request()
    if not r then
        error("no request found")
    end

    C.ngx_http_apisix_enable_ntls(r, 0)
end


return _M
