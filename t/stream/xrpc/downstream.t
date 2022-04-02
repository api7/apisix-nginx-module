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
