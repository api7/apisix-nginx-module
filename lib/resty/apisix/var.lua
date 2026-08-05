-- Index based access to the NGINX variables that are already indexed by the
-- configuration, skipping the name normalization plus hash lookup (and the
-- per-access r->pool allocation) that ngx.var does on every read.
--
-- Only variables present in cmcf->variables are exposed. NGINX itself resolves
-- those through ngx_http_get_indexed_variable() already, so reading them by
-- index is semantically identical to reading them by name. Marking extra
-- variables as indexed via the `apisix_var_index` directive does change the
-- caching semantics of that variable -- see the README.
local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string
local ngx = ngx
local ngx_var = ngx.var
local error = error
local tostring = tostring
local type = type


base.allows_subsystem("http")


-- size_t stands in for ngx_uint_t on the argument side: both are uintptr_t
-- wide, and declaring the index narrower than the callee expects would leave
-- the upper half of the argument register undefined. The count is declared as
-- unsigned int so that LuaJIT hands back a plain number instead of boxed
-- uint64_t cdata; the number of variables never comes close to 2^32.
ffi.cdef[[
unsigned int
ngx_http_apisix_ffi_var_load_indexes(ngx_str_t *names, size_t max);
int
ngx_http_apisix_ffi_var_get_by_index(ngx_http_request_t *r, size_t index,
    unsigned char **value, size_t *value_len);
int
ngx_http_apisix_ffi_var_set_by_index(ngx_http_request_t *r, size_t index,
    const unsigned char *value, size_t value_len, char **err);
]]


local NGX_OK       = 0
local NGX_ERROR    = -1

local value_ptr     = ffi_new("unsigned char *[1]")
local value_len_ptr = ffi_new("size_t[1]")
local err_ptr       = ffi_new("char *[1]")

local indexes = {}


local _M = {indexes = indexes}


-- Build the name -> index map. Must run in the init_worker phase or later:
-- before ngx_init_cycle() commits, the ngx_cycle global still points at the
-- previous cycle.
function _M.load_indexes()
    local phase = ngx.get_phase()
    if phase == "init" then
        error("load_indexes() can not be called in the init phase", 2)
    end

    local count = C.ngx_http_apisix_ffi_var_load_indexes(nil, 0)
    if count == 0 then
        return indexes
    end

    local names = ffi_new("ngx_str_t[?]", count)
    count = C.ngx_http_apisix_ffi_var_load_indexes(names, count)

    for i = 0, count - 1 do
        indexes[ffi_str(names[i].data, names[i].len)] = i
    end

    return indexes
end


function _M.get_by_index(index, r)
    if type(index) ~= "number" then
        error("bad variable index", 2)
    end

    r = r or get_request()
    if not r then
        error("no request found", 2)
    end

    local rc = C.ngx_http_apisix_ffi_var_get_by_index(r, index, value_ptr,
                                                      value_len_ptr)
    if rc ~= NGX_OK then
        return nil
    end

    return ffi_str(value_ptr[0], value_len_ptr[0])
end


function _M.set_by_index(index, value, r)
    if type(index) ~= "number" then
        error("bad variable index", 2)
    end

    r = r or get_request()
    if not r then
        error("no request found", 2)
    end

    local rc
    if value == nil then
        rc = C.ngx_http_apisix_ffi_var_set_by_index(r, index, nil, 0, err_ptr)
    else
        if type(value) ~= "string" then
            value = tostring(value)
        end
        rc = C.ngx_http_apisix_ffi_var_set_by_index(r, index, value,
                                                    #value, err_ptr)
    end

    if rc == NGX_ERROR then
        return nil, ffi_str(err_ptr[0])
    end

    return true
end


-- Falls back to ngx.var for anything the configuration did not index.
function _M.get(name, r)
    local index = indexes[name]
    if not index then
        return ngx_var[name]
    end

    return _M.get_by_index(index, r)
end


function _M.set(name, value, r)
    local index = indexes[name]
    if not index then
        ngx_var[name] = value
        return true
    end

    return _M.set_by_index(index, value, r)
end


return _M
