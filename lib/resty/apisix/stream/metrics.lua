local ffi = require("ffi")
local base = require("resty.core.base")
local get_request = base.get_request
local C = ffi.C
local ffi_str = ffi.string
local tonumber = tonumber
local type = type
local concat = table.concat
local nkeys = require("table.nkeys")
local str_find = string.find
local str_sub = string.sub
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
    uint32_t        labels_len;
    unsigned char   labels[512];
    uint64_t        active;
    uint64_t        bytes[4];
} ngx_stream_apisix_metrics_entry_t;

typedef uintptr_t       ngx_uint_t;

ngx_int_t
ngx_stream_apisix_metrics_dump(ngx_stream_apisix_metrics_entry_t *entries, ngx_uint_t max);

ngx_int_t
ngx_stream_apisix_metrics_size(void);

ngx_int_t
ngx_stream_apisix_metrics_set_labels(void *r, const unsigned char *labels, size_t len);
]])


-- must stay in sync with ngx_stream_apisix_metrics_module.h
local MAX_LABELS_LEN = 512
local DOWNSTREAM_INGRESS = 0
local DOWNSTREAM_EGRESS = 1
local UPSTREAM_EGRESS = 2
local UPSTREAM_INGRESS = 3

-- The zone keys a slot by one byte string, so the label values are joined
-- with a control character that no sensible label value carries.
local SEP = "\31"

local NGX_OK = ngx.OK
local NGX_DECLINED = ngx.DECLINED
local NGX_BUSY = -3

-- grown on demand: labels make the slot count a runtime property of the zone
local entries
local entries_size = 0

-- the stream module is a separate addon, so a build can lack it entirely;
-- resolve the symbol once rather than letting every call throw. The size
-- reader came with labels, so an older build without it is refused too
-- rather than read with the wrong entry layout.
local has_dump = pcall(function()
    return C.ngx_stream_apisix_metrics_size
end)

local _M = {}


local function split_labels(encoded)
    local labels = {}
    if encoded == "" then
        return labels
    end

    local n = 0
    local from = 1
    while true do
        local sep = str_find(encoded, SEP, from, true)
        n = n + 1
        if not sep then
            labels[n] = str_sub(encoded, from)
            return labels
        end

        labels[n] = str_sub(encoded, from, sep - 1)
        from = sep + 1
    end
end


-- Returns an array of per listening address and label set counters:
--   { listen_addr = "0.0.0.0:9100", labels = { "svc-a", "r1" }, active = 3,
--     downstream_ingress = 12, downstream_egress = 34,
--     upstream_ingress = 34, upstream_egress = 12 }
-- The entry with no labels holds the sessions that were never labelled.
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
            labels = split_labels(ffi_str(e.labels, e.labels_len)),
            active = tonumber(e.active),
            downstream_ingress = tonumber(e.bytes[DOWNSTREAM_INGRESS]),
            downstream_egress = tonumber(e.bytes[DOWNSTREAM_EGRESS]),
            upstream_egress = tonumber(e.bytes[UPSTREAM_EGRESS]),
            upstream_ingress = tonumber(e.bytes[UPSTREAM_INGRESS]),
        }
    end

    return res
end


-- Accounts the current stream session, from now on, under the label values
-- in `labels` (an array of strings, in the order the caller's metric declares
-- its labels) on its listening address. An empty array moves the session
-- back to the unlabelled slot.
-- Returns true, or nil and an error; "not accounted" means there is no zone
-- or the listening address has no slot, which is not a failure of the caller.
function _M.set_labels(labels)
    if subsystem ~= "stream" then
        return nil, "only available in the stream subsystem"
    end

    if not has_dump then
        return nil, "this runtime has no stream metrics support"
    end

    -- a map or an array with holes would otherwise join to fewer values than
    -- it holds, and an empty join silently means the unlabelled slot
    if type(labels) ~= "table" or nkeys(labels) ~= #labels then
        return nil, "labels must be an array of strings"
    end

    for i = 1, #labels do
        local value = labels[i]
        if type(value) ~= "string" then
            return nil, "label " .. i .. " must be a string"
        end

        if str_find(value, SEP, 1, true) then
            return nil, "label " .. i .. " contains the \\31 separator"
        end
    end

    local encoded = concat(labels, SEP)
    if #encoded > MAX_LABELS_LEN then
        return nil, "labels take more than " .. MAX_LABELS_LEN .. " bytes"
    end

    local r = get_request()
    if not r then
        return nil, "no request found"
    end

    local rc = C.ngx_stream_apisix_metrics_set_labels(r, encoded, #encoded)
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
