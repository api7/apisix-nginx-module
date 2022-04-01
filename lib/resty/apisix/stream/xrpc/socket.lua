local base = require("resty.core.base")
local ffi = require("ffi")
local ffi_str = ffi.string
local C = ffi.C
local FFI_AGAIN = base.FFI_AGAIN
local FFI_DONE = base.FFI_DONE
local FFI_ERROR = base.FFI_ERROR
local get_string_buf = base.get_string_buf
local get_size_ptr = base.get_size_ptr
local get_request = base.get_request
local co_yield = coroutine._yield
local tab_clone = require("table.clone")


base.allows_subsystem("stream")


ffi.cdef[[
typedef unsigned char u_char;
typedef struct ngx_stream_lua_socket_tcp_upstream_s
    ngx_stream_lua_socket_tcp_upstream_t;

int
ngx_stream_lua_ffi_socket_tcp_read_buf(ngx_stream_lua_request_t *r,
    ngx_stream_lua_socket_tcp_upstream_t *u, u_char **res, size_t len,
    u_char *errbuf, size_t *errbuf_size);

int
ngx_stream_lua_ffi_socket_tcp_get_read_buf_result(ngx_stream_lua_request_t *r,
    ngx_stream_lua_socket_tcp_upstream_t *u, u_char **res, size_t len,
    u_char *errbuf, size_t *errbuf_size);
]]
local socket_tcp_read = C.ngx_stream_lua_ffi_socket_tcp_read_buf
local socket_tcp_get_read_result = C.ngx_stream_lua_ffi_socket_tcp_get_read_buf_result


local ERR_BUF_SIZE = 256
local SOCKET_CTX_INDEX = 1
local resbuf = ffi.new("u_char*[1]")
local Downstream = {}
local Upstream = {}
local downstream_mt
local upstream_mt


local function get_tcp_socket(cosocket)
    local tcp_socket = cosocket[SOCKET_CTX_INDEX]
    if not tcp_socket then
        return error("bad tcp socket", 3)
    end

    return tcp_socket
end


-- read the given length of data to a buffer in C land and return the buffer address
-- return error if the read data is less than given length
local function read_buf(cosocket, len)
    if len <= 0 then
        error("bad length: length of data should be positive, got " .. len, 2)
    end

    if len > 4 * 1024 * 1024 then
        error("bad length: length of data too big, got " .. len, 2)
    end

    local r = get_request()
    if not r then
        error("no request found", 2)
    end

    local u = get_tcp_socket(cosocket)
    local errbuf = get_string_buf(ERR_BUF_SIZE)
    local errbuf_size = get_size_ptr()
    errbuf_size[0] = ERR_BUF_SIZE

    local rc = socket_tcp_read(r, u, resbuf, len, errbuf, errbuf_size)
    if rc == FFI_DONE then
        error(ffi_str(errbuf, errbuf_size[0]), 2)
    end

    while true do
        if rc == FFI_ERROR then
            return nil, ffi_str(errbuf, errbuf_size[0])
        end

        if rc >= 0 then
            return resbuf[0]
        end

        assert(rc == FFI_AGAIN)

        co_yield()

        errbuf = get_string_buf(ERR_BUF_SIZE)
        errbuf_size = get_size_ptr()
        errbuf_size[0] = ERR_BUF_SIZE
        rc = socket_tcp_get_read_result(r, u, resbuf, len, errbuf, errbuf_size)
    end
end


local function patch_methods(sk)
    local methods = getmetatable(sk).__index
    local copy = tab_clone(methods)
    -- need to remove methods which will break the buffer management
    copy.receive = nil
    copy.receiveany = nil
    copy.receiveuntil = nil

    copy.read = read_buf

    return {__index = copy}
end


local function set_method_table(sk, is_downstream)
    if is_downstream then
        if not downstream_mt then
            downstream_mt = patch_methods(sk)
        end
        return setmetatable(sk, downstream_mt)
    end

    if not upstream_mt then
        upstream_mt = patch_methods(sk)
    end
    return setmetatable(sk, upstream_mt)
end


function Downstream.socket()
    return set_method_table(ngx.req.socket(true), true)
end


function Upstream.socket()
    return set_method_table(ngx.socket.tcp(), false)
end


return {
    downstream = Downstream,
    upstream = Upstream,
}
