local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local ffi_str = ffi.string
local tonumber = tonumber
local type = type
local subsystem = ngx.config.subsystem


-- No allows_subsystem() guard: the zone is process global and the reader
-- touches neither a session nor any stream context, so http can read it too.


-- the request is declared as void * so that this also loads in http, where
-- ngx_stream_lua_request_t is not a known type
ffi.cdef([[
typedef intptr_t        ngx_int_t;

typedef struct {
    unsigned char   addr[128];
    uint32_t        addr_len;
    uint32_t        label_len;
    unsigned char   label[512];
    uint64_t        active;
    uint64_t        bytes[4];
} ngx_stream_apisix_metrics_entry_t;

typedef uintptr_t       ngx_uint_t;

ngx_int_t
ngx_stream_apisix_metrics_dump(ngx_stream_apisix_metrics_entry_t *entries, ngx_uint_t max);

ngx_int_t
ngx_stream_apisix_metrics_size(void);

ngx_int_t
ngx_stream_apisix_metrics_set_label(void *r, const unsigned char *label, size_t len);
]])


-- must stay in sync with ngx_stream_apisix_metrics_module.h
local MAX_LABEL_LEN = 512
local DOWNSTREAM_INGRESS = 0
local DOWNSTREAM_EGRESS = 1
local UPSTREAM_EGRESS = 2
local UPSTREAM_INGRESS = 3

local NGX_OK = ngx.OK
local NGX_DECLINED = ngx.DECLINED
local NGX_BUSY = -3

-- grown on demand: labels make the slot count a runtime property of the zone
local entries
local entries_size = 0

-- the stream module is a separate addon, so a build can lack it entirely;
-- resolve the symbol once rather than letting every call throw
local has_dump = pcall(function()
    return C.ngx_stream_apisix_metrics_dump
end)

local _M = {}


-- Returns an array of per listening address and label counters:
--   { listen_addr = "0.0.0.0:9100", label = "", active = 3,
--     downstream_ingress = 12, downstream_egress = 34,
--     upstream_ingress = 34, upstream_egress = 12 }
-- The entry with an empty label holds the sessions that were never labelled.
-- The byte counters are monotonic totals since the zone was created.
function _M.dump()
    if not has_dump then
        return nil, "this runtime has no stream metrics support"
    end

    local size = tonumber(C.ngx_stream_apisix_metrics_size())
    if size < 0 then
        return nil, "stream metrics zone is not configured"
    end

    if size > entries_size then
        entries = ffi.new("ngx_stream_apisix_metrics_entry_t[?]", size)
        entries_size = size
    end

    if size == 0 then
        return {}
    end

    -- slots claimed after the size was taken are simply read next time
    local n = tonumber(C.ngx_stream_apisix_metrics_dump(entries, entries_size))
    if n < 0 then
        return nil, "stream metrics zone is not configured"
    end

    local res = {}
    for i = 0, n - 1 do
        local e = entries[i]
        res[i + 1] = {
            listen_addr = ffi_str(e.addr, e.addr_len),
            label = ffi_str(e.label, e.label_len),
            active = tonumber(e.active),
            downstream_ingress = tonumber(e.bytes[DOWNSTREAM_INGRESS]),
            downstream_egress = tonumber(e.bytes[DOWNSTREAM_EGRESS]),
            upstream_egress = tonumber(e.bytes[UPSTREAM_EGRESS]),
            upstream_ingress = tonumber(e.bytes[UPSTREAM_INGRESS]),
        }
    end

    return res
end


-- Accounts the current stream session, from now on, under `label` on its
-- listening address. The label is an opaque string: a caller that needs
-- several dimensions encodes them into it. An empty label moves the session
-- back to the unlabelled slot.
-- Returns true, or nil and an error; "not accounted" means there is no zone
-- or the listening address has no slot, which is not a failure of the caller.
function _M.set_label(label)
    if subsystem ~= "stream" then
        return nil, "only available in the stream subsystem"
    end

    if not has_dump then
        return nil, "this runtime has no stream metrics support"
    end

    if type(label) ~= "string" then
        return nil, "label must be a string"
    end

    if #label > MAX_LABEL_LEN then
        return nil, "label is longer than " .. MAX_LABEL_LEN .. " bytes"
    end

    local r = get_request()
    if not r then
        return nil, "no request found"
    end

    local rc = C.ngx_stream_apisix_metrics_set_label(r, label, #label)
    if rc == NGX_OK then
        return true
    end

    if rc == NGX_DECLINED then
        return nil, "not accounted"
    end

    if rc == NGX_BUSY then
        return nil, "stream metrics zone is full"
    end

    return nil, "failed to label the session"
end


return _M
