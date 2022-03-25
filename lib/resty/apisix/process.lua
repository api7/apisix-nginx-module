local ffi = require("ffi")
local C = ffi.C
local tonumber = tonumber


ffi.cdef[[
typedef uintptr_t       ngx_uint_t;
ngx_uint_t
ngx_worker_process_get_last_reopen_ms();
]]
local _M = {}


function _M.get_last_reopen_ms()
    return tonumber(C.ngx_worker_process_get_last_reopen_ms())
end


return _M
