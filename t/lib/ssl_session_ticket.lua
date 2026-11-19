-- Helpers for the session ticket takeover tests, loaded as
-- require("t.lib.ssl_session_ticket") (the tests run from the repository root).
--
-- The client side runs in the http subsystem: it connects to a TLS endpoint,
-- offers a previous session, and reads back what the server reports, i.e.
-- "<$ssl_session_reused> <$ssl_protocol> <tickets of the connection>". The
-- session it ends up with tells which key encrypted its ticket: the ticket of
-- a stateless session starts with the 16 byte name of that key.
local ffi = require("ffi")
local ticket = require("resty.apisix.ssl_session_ticket")
local C = ffi.C
local ffi_str = ffi.string
local str_char = string.char
local str_format = string.format
local str_rep = string.rep
local tonumber = tonumber


ffi.cdef[[
int SSL_SESSION_has_ticket(const void *s);
void SSL_SESSION_get0_ticket(const void *s, const unsigned char **tick,
    size_t *len);
]]


local tick = ffi.new("const unsigned char *[1]")
local tick_len = ffi.new("size_t[1]")


local _M = {
    -- phase name => true: the TLS servers of the tests hold every handshake
    -- in that phase until the flag is cleared, so that a test can change the
    -- context meanwhile; held counts the handshakes waiting there
    hold = {},
    held = {},
    -- whether ssl_client_hello_by_lua* aligns the connection: client_hello()
    sync = true,
}


local function hold(phase)
    if not _M.hold[phase] then
        return
    end

    _M.held[phase] = (_M.held[phase] or 0) + 1

    while _M.hold[phase] do
        ngx.sleep(0.01)
    end

    _M.held[phase] = _M.held[phase] - 1
end


-- waits until a handshake is held in the phase, see _M.hold
function _M.wait_held(phase)
    for _ = 1, 1000 do
        if (_M.held[phase] or 0) > 0 then
            return
        end

        ngx.sleep(0.01)
    end

    error("no handshake reached " .. phase)
end


-- test key n: name(16) | HMAC(32) | AES(32), each filled with one byte
function _M.key(n)
    return str_rep(str_char(n), 16) .. str_rep(str_char(n + 100), 32)
           .. str_rep(str_char(n + 200), 32)
end


-- the name of test key n as the logs and _M.connect() show it
function _M.name(n)
    return str_rep(str_format("%02x", n), 16)
end


local function hex(s)
    return (s:gsub(".", function (c)
        return str_format("%02x", c:byte())
    end))
end


-- what the ticket of a session is: nil without one, "stateful" for the
-- session id a TLSv1.3 server sends when stateless tickets are off, or the
-- hex name of the key a stateless ticket is encrypted with
local function ticket_of(sess)
    if sess == nil or C.SSL_SESSION_has_ticket(sess) == 0 then
        return nil
    end

    C.SSL_SESSION_get0_ticket(sess, tick, tick_len)

    local len = tonumber(tick_len[0])
    -- key name, IV, encrypted session and HMAC: well above 64 bytes
    if len <= 64 then
        return "stateful", ffi_str(tick[0], len)
    end

    local bytes = ffi_str(tick[0], len)
    return hex(bytes:sub(1, 16)), bytes
end


-- Connects to addr and completes a TLS handshake, resuming opts.session if
-- given. An http endpoint gets a request first (opts.http). Returns
--   { reused = true|false, protocol = "TLSv1.3", conn_tickets = "1",
--     ticket = <see ticket_of()>, ticket_bytes = ..., session = <cdata> }
-- or nil and an error.
function _M.connect(addr, opts)
    opts = opts or {}

    local sock = ngx.socket.tcp()
    sock:settimeout(opts.timeout or 5000)

    local ok, err = sock:connect(addr)
    if not ok then
        return nil, "connect: " .. err
    end

    local sess, err = sock:tlshandshake({
        reused_session = opts.session,
        server_name = "test.com",
    })
    if not sess then
        return nil, "handshake: " .. err
    end

    if opts.http then
        local ok, err = sock:send("GET / HTTP/1.0\r\nHost: test.com\r\n\r\n")
        if not ok then
            return nil, "send: " .. err
        end
    end

    local data, err = sock:receive("*a")
    if not data then
        return nil, "receive: " .. err
    end

    local reused, protocol, conn_tickets =
        data:match("(%S+) (%S+) (%S+)\n$")
    if not reused then
        return nil, "unexpected response: " .. data
    end

    -- the session after the response carries what TLSv1.3 sends late
    local session = sock:getsslsession()
    sock:close()

    local name, bytes = ticket_of(session)

    return {
        reused = reused == "r",
        protocol = protocol,
        conn_tickets = conn_tickets,
        ticket = name,
        ticket_bytes = bytes,
        session = session,
    }
end


-- for the response of a TLS server: whether its connection may use tickets
function _M.conn_tickets()
    local on, err = ticket.connection_tickets()
    if on == nil then
        return err
    end

    return on and "1" or "0"
end


-- what the TLS servers report about the current connection
function _M.state_line()
    return ngx.var.ssl_session_reused .. " " .. ngx.var.ssl_protocol
           .. " " .. _M.conn_tickets()
end


-- content_by_lua* of the TLS servers: what connect() reads back
function _M.respond()
    local body = _M.state_line() .. "\n"

    if ngx.config.subsystem == "http" then
        -- keeps an HTTP/1.1 connection open for request()
        ngx.header["Content-Length"] = #body
    end

    ngx.print(body)
end


-- content_by_lua* of a stream TLS server that stays open: answers each line
-- with state_line(), until the client closes
function _M.serve_lines()
    local sock = assert(ngx.req.socket(true))

    while true do
        local line = sock:receive("*l")
        if not line then
            return
        end

        assert(sock:send(_M.state_line() .. "\n"))
    end
end


-- sends a request on an open HTTP/1.1 connection, returns the response body
-- without its newline
function _M.request(sock)
    assert(sock:send("GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"))

    local len
    while true do
        local line = assert(sock:receive("*l"))
        if line == "" then
            break
        end

        len = len or tonumber(line:match("^[Cc]ontent%-[Ll]ength: (%d+)"))
    end

    local body = assert(sock:receive(len))
    return (body:gsub("\n$", ""))
end


-- for ssl_client_hello_by_lua* of the TLS servers
function _M.client_hello()
    hold("client_hello")

    if _M.sync then
        local ok, err = ticket.sync_connection()
        if ok == nil then
            ngx.log(ngx.ERR, "failed to sync the connection: ", err)
        end
    end
end


-- for ssl_certificate_by_lua* of the TLS servers
function _M.certificate()
    hold("certificate")
end


-- the list of keys with the given test numbers
function _M.keys(...)
    local keys = {}
    for i = 1, select("#", ...) do
        keys[i] = _M.key(select(i, ...))
    end

    return keys
end


-- Installs test keys on a context and turns tickets on, in the safe order.
function _M.enable(id, ...)
    assert(ticket.set_keys(id, _M.keys(...)))
    assert(ticket.enable_tickets(id))
end


-- Turns tickets off and drops the keys, in the safe order.
function _M.disable(id)
    assert(ticket.disable_tickets(id))
    assert(ticket.revoke_keys(id))
end


-- A line protocol for the stream subsystem, whose contexts only its own VM
-- reaches: the http test client sends one command per connection to a stream
-- server running control(), and reads the answer.
--   "enable <id> <n>..."   "disable <id>"   "set_keys <id> <n>..."
--   "enable_tickets <id>"  "disable_tickets <id>"   "revoke_keys <id>"
--   "contexts"   "hold <phase> on|off"   "held <phase>"   "sync on|off"
local commands = {}

function commands.enable(id, ...)
    _M.enable(tonumber(id), _M.numbers(...))
    return "ok"
end

function commands.disable(id)
    _M.disable(tonumber(id))
    return "ok"
end

function commands.set_keys(id, ...)
    local ok, err = ticket.set_keys(tonumber(id), _M.keys(_M.numbers(...)))
    return ok and "ok" or err
end

function commands.enable_tickets(id)
    local ok, err = ticket.enable_tickets(tonumber(id))
    return ok and "ok" or err
end

function commands.disable_tickets(id)
    local ok, err = ticket.disable_tickets(tonumber(id))
    return ok and "ok" or err
end

function commands.revoke_keys(id)
    local ok, err = ticket.revoke_keys(tonumber(id))
    return ok and "ok" or err
end

function commands.contexts()
    return _M.dump_contexts()
end

function commands.hold(phase, on)
    _M.hold[phase] = on == "on" or nil
    return "ok"
end

function commands.held(phase)
    return tostring(_M.held[phase] or 0)
end

function commands.sync(on)
    _M.sync = on == "on"
    return "ok"
end


function _M.numbers(...)
    local res = {}
    for i = 1, select("#", ...) do
        res[i] = tonumber((select(i, ...)))
    end

    return unpack(res)
end


-- one line per context: "<id> registered=<..> tickets=<..> keys=<n>"
function _M.dump_contexts()
    local ctxs, err = ticket.contexts()
    if not ctxs then
        return err
    end

    local lines = {}
    for i, ctx in ipairs(ctxs) do
        lines[i] = str_format("%d registered=%s tickets=%s keys=%d",
                              ctx.id, ctx.registered, ctx.tickets, ctx.keys)
    end

    return #lines > 0 and table.concat(lines, "\n") or "none"
end


-- content_by_lua* of the stream control server
function _M.control()
    local sock = assert(ngx.req.socket(true))
    local line = assert(sock:receive("*l"))

    local args = {}
    for word in line:gmatch("%S+") do
        args[#args + 1] = word
    end

    local cmd = commands[args[1]]
    local res = cmd and cmd(unpack(args, 2)) or "unknown command"
    assert(sock:send(res .. "\n"))
end


-- the http side of control(): sends a command to the stream control server
-- listening on `ctl`, and returns its answer
function _M.stream(ctl, cmd)
    local sock = ngx.socket.tcp()
    sock:settimeout(5000)
    assert(sock:connect(ctl))
    assert(sock:send(cmd .. "\n"))

    local data = assert(sock:receive("*a"))
    sock:close()

    return (data:gsub("\n$", ""))
end


-- _M.wait_held() for the stream servers, from the http side
function _M.stream_wait_held(ctl, phase)
    for _ = 1, 1000 do
        if _M.stream(ctl, "held " .. phase) ~= "0" then
            return
        end

        ngx.sleep(0.01)
    end

    error("no stream handshake reached " .. phase)
end


return _M
