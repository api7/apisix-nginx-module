local ffi = require("ffi")
local C = ffi.C
local tonumber = tonumber
local pcall = pcall
local require = require


ffi.cdef[[
uint64_t
ngx_worker_process_get_last_reopen_ms();

uintptr_t
ngx_apisix_get_generation(void);
]]
local _M = {}


-- a runtime without this module's http addon has no generation; resolve the
-- symbol once rather than letting every call throw
local has_generation = pcall(function()
    return C.ngx_apisix_get_generation
end)


function _M.get_last_reopen_ms()
    return tonumber(C.ngx_worker_process_get_last_reopen_ms())
end


-- The configuration generation of this process: 1 for the configuration the
-- master started with, then one more for each successful reload. A worker
-- keeps the generation it was started for, so the workers of two overlapping
-- generations tell apart, which ngx.worker.id() does not. 0 until the first
-- configuration is in place, in init_by_lua* for instance.
-- The count starts over when nginx restarts, along with its shared memory.
function _M.get_generation()
    if not has_generation then
        return nil, "not supported"
    end

    return tonumber(C.ngx_apisix_get_generation())
end


-- Returns what identifies this process among the processes that run at the
-- same time under one master:
--   { type = "worker", pid = 1234, worker_id = 0, worker_count = 4,
--     generation = 3, slot = 0 }
-- slot is the worker id for a worker (or a single process), worker_count
-- for the privileged agent and nil for any other process. Within a
-- generation it is bounded by worker_count, and a worker that is restarted
-- after a crash gets the slot back, with a new pid.
function _M.get_identity()
    local generation, err = _M.get_generation()
    if not generation then
        return nil, err
    end

    -- loaded here so that an older lua-resty-core, whose ngx.process may not
    -- cover the subsystem, cannot keep the rest of this module from loading
    local ok, ngx_process = pcall(require, "ngx.process")
    if not ok then
        return nil, "not supported"
    end

    local typ = ngx_process.type()
    local worker_id = ngx.worker.id()
    local worker_count = ngx.worker.count()

    local slot
    if typ == "worker" or typ == "single" then
        slot = worker_id

    elseif typ == "privileged agent" then
        slot = worker_count
    end

    return {
        type = typ,
        pid = ngx.worker.pid(),
        worker_id = worker_id,
        worker_count = worker_count,
        generation = generation,
        slot = slot,
    }
end


return _M
