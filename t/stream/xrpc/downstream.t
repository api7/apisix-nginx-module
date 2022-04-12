use t::APISIX_NGINX 'no_plan';

run_tests();

__DATA__

=== TEST 1: inherit methods from raw socket
--- stream_server_config
    content_by_lua_block {
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:send("world")

        assert(sk.receiveany == nil)
        assert(sk.receiveuntil == nil)
        assert(sk.receive == nil)
    }
--- stream_request
--- stream_response chomp
world



=== TEST 2: read
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:settimeout(5)
        local p = assert(sk:read(4))
        ngx.say(ffi.string(p, 4))
        local p = assert(sk:read(4))
        ngx.say(ffi.string(p, 3))
        local p = assert(sk:read(1))
        ngx.say(ffi.string(p, 1))

        local p, err = sk:read(5)
        ngx.say(p)
        ngx.say(err)
        local p, err = sk:read(5)
        ngx.say(p)
        ngx.say(err)
    }
--- error_log
socket read timed out
--- stream_request
hello world
--- stream_response
hell
o w
r
nil
timeout
nil
timeout



=== TEST 3: read with peek
--- stream_server_config
    preread_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:settimeout(5)
        sk:peek(4)
        local p = assert(sk:read(9))
        ngx.say(ffi.string(p, 9))
        ngx.exit(200)
    }
    proxy_pass 127.0.0.1:1990;
--- stream_request
hello world
--- stream_response
hello wor



=== TEST 4: read with peek (peeked data > read)
--- stream_server_config
    preread_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:settimeout(5)
        sk:peek(11)
        local p = assert(sk:read(9))
        ngx.say(ffi.string(p, 9))
        ngx.exit(200)
    }
    proxy_pass 127.0.0.1:1990;
--- stream_request
hello world
--- stream_response
hello wor



=== TEST 5: read over buffer
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:settimeout(5)
        local len = 9 * 1024
        local p = assert(sk:read(len))
        ngx.print(ffi.string(p, len))
    }
--- stream_request eval
"123456789" x 1024
--- stream_response eval
"123456789" x 1024



=== TEST 6: read over buffer in the middle
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:settimeout(5)
        local len = 9 * 256
        local p = assert(sk:read(len))
        ngx.say(ffi.string(p, len))
        local p = assert(sk:read(len))
        ngx.say(ffi.string(p, len))

        local len = 9 * 512
        local p = assert(sk:read(len))
        ngx.print(ffi.string(p, len))
    }
--- stream_request eval
"123456789" x 1024
--- stream_response eval
"123456789" x 256 .
"\n" .
"123456789" x 256 .
"\n" .
"123456789" x 512
--- grep_error_log eval
qr/stream lua tcp socket allocate new new buf of size \d+/
--- grep_error_log_out
stream lua tcp socket allocate new new buf of size 4096
stream lua tcp socket allocate new new buf of size 4096
stream lua tcp socket allocate new new buf of size 4608



=== TEST 7: read & move
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            local exp = {
                "hell",
                "o wo",
                "r",
            }
            for i = 1, 3 do
                local data = sk:receiveany(128)
                if data ~= exp[i] then
                    ngx.log(ngx.ERR, "actual: ", data, ", expected: ", exp[i])
                end
            end
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        ds:settimeout(5)

        local us = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        us:settimeout(50)
        assert(us:connect("127.0.0.1", 1995))

        local p = assert(ds:read(4))
        assert(us:move(ds))
        ngx.sleep(0.01)
        local p = assert(ds:read(4))
        assert(us:move(ds))
        ngx.sleep(0.01)
        local p = assert(ds:read(1))
        assert(us:move(ds))
    }
--- stream_request
hello world



=== TEST 8: multiple moves
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            local data = sk:receiveany(128)
            local exp = "hello wor"
            if data ~= exp then
                ngx.log(ngx.ERR, "actual: ", data, ", expected: ", exp)
            end
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        ds:settimeout(5)

        local us = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        us:settimeout(50)
        assert(us:connect("127.0.0.1", 1995))

        local p = assert(ds:read(4))
        local p = assert(ds:read(4))
        local p = assert(ds:read(1))
        assert(us:move(ds))
    }
--- stream_request
hello world



=== TEST 9: multiple moves + read over buffer in the middle
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            local data = sk:receive(9 * 24)
            local exp = ("123456789"):rep(24)
            if data ~= exp then
                ngx.log(ngx.ERR, "actual: ", data, ", expected: ", exp)
            end
        }
    }
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:settimeout(5)

        local us = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        us:settimeout(50)
        assert(us:connect("127.0.0.1", 1995))

        local len = 9 * 8
        local p = assert(sk:read(len))
        local len = 9 * 16
        local p = assert(sk:read(len))
        assert(us:move(sk))
    }
--- stream_request eval
"123456789" x 24
--- grep_error_log eval
qr/stream lua tcp socket allocate new new buf of size \d+/
--- grep_error_log_out
stream lua tcp socket allocate new new buf of size 128
stream lua tcp socket allocate new new buf of size 144



=== TEST 10: drain & move
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            local exp = {
                "hell",
                "o wo",
                "r",
            }
            for i = 1, 3 do
                local data = sk:receiveany(128)
                if data ~= exp[i] then
                    ngx.log(ngx.ERR, "actual: ", data, ", expected: ", exp[i])
                end
            end
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        ds:settimeout(5)

        local us = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        us:settimeout(50)
        assert(us:connect("127.0.0.1", 1995))

        assert(ds:drain(4))
        assert(us:move(ds))
        ngx.sleep(0.01)
        assert(ds:drain(4))
        assert(us:move(ds))
        ngx.sleep(0.01)
        assert(ds:drain(1))
        assert(us:move(ds))
    }
--- stream_request
hello world



=== TEST 11: read & drain & move & reset_read_buf
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            local data = sk:receiveany(128)
            local exp = "rld"
            if data ~= exp then
                ngx.log(ngx.ERR, "actual: ", data, ", expected: ", exp)
            end
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        ds:settimeout(5)

        local us = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        us:settimeout(50)
        assert(us:connect("127.0.0.1", 1995))

        assert(ds:read(4))
        assert(ds:drain(4))
        ds:reset_read_buf()
        assert(us:move(ds))
        assert(ds:drain(3))
        assert(us:move(ds))
    }
--- stream_request
hello world



=== TEST 12: move & reset_read_buf + read over buffer in the middle
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            local data = sk:receive(9 * 8)
            local exp = ("123456789"):rep(8)
            if data ~= exp then
                ngx.log(ngx.ERR, "actual: ", data, ", expected: ", exp)
            end
        }
    }
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:settimeout(5)

        local us = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        us:settimeout(50)
        assert(us:connect("127.0.0.1", 1995))

        local len = 9 * 8
        local p = assert(sk:read(len))
        local len = 9 * 16
        local p = assert(sk:read(len))
        sk:reset_read_buf()
        local len = 9 * 8
        local p = assert(sk:read(len))
        assert(us:move(sk))
    }
--- stream_request eval
"123456789" x 32
