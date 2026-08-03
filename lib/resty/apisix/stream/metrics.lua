local ffi = require("ffi")
local base = require("resty.core.base")
local C = ffi.C
local ffi_str = ffi.string
local tonumber = tonumber


base.allows_subsystem("stream")


ffi.cdef([[
typedef intptr_t        ngx_int_t;

typedef struct {
    unsigned char   addr[128];
    uint32_t        addr_len;
    uint64_t        active;
    uint64_t        bytes[4];
} ngx_stream_apisix_metrics_entry_t;

ngx_int_t
ngx_stream_apisix_metrics_dump(ngx_stream_apisix_metrics_entry_t *entries, size_t max);
]])


-- must stay in sync with ngx_stream_apisix_metrics_module.h
local MAX_ENTRIES = 512
local DOWNSTREAM_INGRESS = 0
local DOWNSTREAM_EGRESS = 1
local UPSTREAM_EGRESS = 2
local UPSTREAM_INGRESS = 3

local entries = ffi.new("ngx_stream_apisix_metrics_entry_t[?]", MAX_ENTRIES)

local _M = {}


-- Returns an array of per listening address counters:
--   { listen_addr = "0.0.0.0:9100", active = 3,
--     downstream_ingress = 12, downstream_egress = 34,
--     upstream_ingress = 34, upstream_egress = 12 }
-- The byte counters are monotonic totals since the zone was created.
function _M.dump()
    local n = C.ngx_stream_apisix_metrics_dump(entries, MAX_ENTRIES)
    n = tonumber(n)
    if n < 0 then
        return nil, "stream metrics zone is not configured"
    end

    local res = {}
    for i = 0, n - 1 do
        local e = entries[i]
        res[i + 1] = {
            listen_addr = ffi_str(e.addr, e.addr_len),
            active = tonumber(e.active),
            downstream_ingress = tonumber(e.bytes[DOWNSTREAM_INGRESS]),
            downstream_egress = tonumber(e.bytes[DOWNSTREAM_EGRESS]),
            upstream_egress = tonumber(e.bytes[UPSTREAM_EGRESS]),
            upstream_ingress = tonumber(e.bytes[UPSTREAM_INGRESS]),
        }
    end

    return res
end


return _M
