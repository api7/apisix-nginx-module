local json = require("cjson.safe")
local tickets = require("resty.apisix.ssl_session_ticket")

local _M = {}
local status = {supported = tickets.is_supported()}

function _M.start(path, cleanup)
    if not status.supported then
        return
    end

    local function ingest(premature)
        if premature then
            return
        end

        local file = assert(io.open(path, "rb"))
        local payload = assert(json.decode(file:read("*a")))
        file:close()
        if payload.sequence == status.sequence then
            return
        end

        local keys = {}
        for position, entry in ipairs(payload.keys) do
            keys[position] = {
                key = assert(ngx.decode_base64(entry.key)),
                encrypt_from = entry.encrypt_from,
                encrypt_until = entry.encrypt_until,
                decrypt_until = entry.decrypt_until,
                lifetime = entry.lifetime,
            }
        end

        local ok, err = tickets.set_keys(keys)
        status.error = not ok and err or nil
        status.sequence = payload.sequence
    end

    ingest(false)
    assert(ngx.timer.every(0.05, ingest))
    if cleanup then
        assert(ngx.timer.every(0.1, function(premature)
            if not premature then
                assert(tickets.expire_keys())
            end
        end))
    end
end

function _M.status()
    status.worker_pid = ngx.worker.pid()
    return status
end

return _M
