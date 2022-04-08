use t::APISIX_NGINX 'no_plan';

run_tests();

__DATA__

=== TEST 1: inherit methods from raw socket
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            local resp = sk:receiveany(10240)
            ngx.log(ngx.WARN, "get resp data: ", resp)
            sk:send(resp)
        }
    }
--- stream_server_config
    content_by_lua_block {
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))
        sk:send("world")
        ngx.sleep(0.001)
        sk:close()

        assert(sk.receiveany == nil)
        assert(sk.receiveuntil == nil)
        assert(sk.receive == nil)
    }
--- stream_request
--- grep_error_log eval
qr/get resp data: \w+/
--- grep_error_log_out
get resp data: world



=== TEST 2: read
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send("hello world")
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))

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
receive data on a closed socket
--- stream_request
--- stream_response
hell
o w
r
nil
closed
nil
closed



=== TEST 3: read over buffer
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send(("123456789"):rep(1024))
            ngx.sleep(0.1)
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))

        sk:settimeout(5)
        local len = 9 * 1024
        local p = assert(sk:read(len))
        ngx.print(ffi.string(p, len))
    }
--- stream_request
--- stream_response eval
"123456789" x 1024



=== TEST 4: read over buffer in the middle
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send(("123456789"):rep(1024))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))
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
--- stream_request
--- stream_response eval
"123456789" x 256 .
"\n" .
"123456789" x 256 .
"\n" .
"123456789" x 512



=== TEST 5: empty move
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send("hello world")
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))

        sk:settimeout(5)
        assert(ds:move(sk))
    }
--- stream_request
--- stream_response



=== TEST 6: move bigger buffer
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send(("123456789"):rep(1024))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))

        sk:settimeout(5)
        local len = 9 * 512
        local p = assert(sk:read(len))

        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(ds:move(sk))
        -- mix send operation
        assert(ds:send("\n"))

        local p = assert(sk:read(len / 2))
        assert(ds:move(sk))
    }
--- stream_request
--- stream_response eval
"123456789" x 512 .
"\n" .
"123456789" x 256



=== TEST 7: read over buffer in the middle, move
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send(("123456789"):rep(256))
            sk:send(("abcdefghi"):rep(512))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))

        sk:settimeout(5)
        local len = 9 * 256
        local p = assert(sk:read(len))
        local p = assert(sk:read(len * 2))

        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(ds:move(sk))
    }
--- stream_request
--- stream_response eval
"123456789" x 256 .
"abcdefghi" x 512



=== TEST 8: read over buffer in the middle, multiple moves
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send(("123456789"):rep(1024))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))

        sk:settimeout(5)
        local len = 9 * 256
        local p = assert(sk:read(len))

        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(ds:move(sk))
        -- mix send operation
        assert(ds:send("\n"))

        local p = assert(sk:read(len * 2))
        assert(ds:move(sk))
    }
--- stream_request
--- stream_response eval
"123456789" x 256 .
"\n" .
"123456789" x 512



=== TEST 9: multiple drain & move
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send(("123456789"):rep(256))
            sk:send(("abcdefghi"):rep(512))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))

        sk:settimeout(5)
        local len = 9 * 256
        sk:drain(len)
        sk:drain(len * 2)

        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(ds:move(sk))
    }
--- stream_request
--- stream_response eval
"123456789" x 256 .
"abcdefghi" x 512
--- grep_error_log eval
qr/stream lua tcp socket allocate new new buf of size \d+/
--- grep_error_log_out
stream lua tcp socket allocate new new buf of size 4096



=== TEST 10: read & drain & move
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send(("123456789"):rep(256))
            sk:send(("abcdefghi"):rep(512))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))

        sk:settimeout(5)
        local len = 9 * 256
        sk:read(len)
        sk:drain(len * 2)

        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(ds:move(sk))
    }
--- stream_request
--- stream_response eval
"123456789" x 256 .
"abcdefghi" x 512
--- grep_error_log eval
qr/stream lua tcp socket allocate new new buf of size \d+/
--- grep_error_log_out
stream lua tcp socket allocate new new buf of size 4096



=== TEST 11: drain & read & move
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            sk:send(("123456789"):rep(256))
            sk:send(("abcdefghi"):rep(512))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))

        sk:settimeout(5)
        local len = 9 * 256
        sk:drain(len)
        sk:read(len * 2)

        local ds = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(ds:move(sk))
    }
--- stream_request
--- stream_response eval
"123456789" x 256 .
"abcdefghi" x 512
--- grep_error_log eval
qr/stream lua tcp socket allocate new new buf of size \d+/
--- grep_error_log_out
stream lua tcp socket allocate new new buf of size 4096
stream lua tcp socket allocate new new buf of size 4608
