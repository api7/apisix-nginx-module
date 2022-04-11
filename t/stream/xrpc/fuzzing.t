use t::APISIX_NGINX 'no_plan';

run_tests();

__DATA__

=== TEST 1: read
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        math.randomseed(ngx.time())

        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:settimeout(5)
        local total = 9 * 1024
        while total > 0 do
            local len = math.random(1, 512)
            if len > total then
                len = total
            end
            total = total - len
            local p = assert(sk:read(len))
            ngx.print(ffi.string(p, len))
        end
    }
--- stream_request eval
"123456789" x 1024
--- stream_response eval
"123456789" x 1024



=== TEST 2: read (upstream)
--- stream_config
    lua_socket_buffer_size 128;
    server {
        listen 1995;
        content_by_lua_block {
            local s = ("123456789"):rep(1024)
            local total = 9 * 1024
            local idx = 1
            while total > 0 do
                local len = math.random(1, 512)
                if len > total then
                    len = total
                end
                total = total - len
                local n, err = ngx.print(s:sub(idx, idx + len - 1))
                if not n then
                    ngx.log(ngx.ERR, err)
                    return
                end
                ngx.flush(true)
                ngx.sleep(0.01)
                idx = idx + len
            end
        }
    }
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        math.randomseed(ngx.time())

        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))
        sk:settimeout(500)
        local total = 9 * 1024
        while total > 0 do
            local len = math.random(1, 512)
            if len > total then
                len = total
            end
            total = total - len
            local p = assert(sk:read(len))
            ngx.print(ffi.string(p, len))
        end
    }
--- stream_request
--- stream_response eval
"123456789" x 1024



=== TEST 3: move
--- stream_config
    lua_socket_buffer_size 128;
    server {
        listen 1995;
        content_by_lua_block {
            local s = ("123456789"):rep(10240)
            local total = 9 * 1024 * 10
            local idx = 1
            while total > 0 do
                local len = math.random(1, 512)
                if len > total then
                    len = total
                end
                total = total - len
                local n, err = ngx.print(s:sub(idx, idx + len - 1))
                if not n then
                    ngx.log(ngx.ERR, err)
                    return
                end
                ngx.flush(true)
                ngx.sleep(0.01)
                idx = idx + len
            end
        }
    }
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        math.randomseed(ngx.time())

        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        local dsk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(sk:connect("127.0.0.1", 1995))
        sk:settimeout(500)
        local total = 9 * 1024 * 10
        while total > 0 do
            local len = math.random(1, 512)
            if len > total then
                len = total
            end
            total = total - len
            local p = assert(sk:read(len))
            dsk:move(sk)
        end
    }
--- stream_request
--- stream_response eval
"123456789" x 10240
--- timeout: 8



=== TEST 4: move (multiple read)
--- stream_config
    lua_socket_buffer_size 128;
    server {
        listen 1995;
        content_by_lua_block {
            local s = ("123456789"):rep(128)
            ngx.say(s)
        }
    }
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        math.randomseed(ngx.time())

        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        local dsk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(sk:connect("127.0.0.1", 1995))
        sk:settimeout(500)
        local total = 9 * 128
        while total > 0 do
            local len = math.random(1, 512)
            if len > total then
                len = total
            end
            total = total - len
            local p = assert(sk:read(len))
            if total % 2 == 0 then
                dsk:move(sk)
            end
        end
    }
--- stream_request
--- stream_response eval
"123456789" x 128



=== TEST 5: move (read & drain)
--- stream_config
    lua_socket_buffer_size 128;
    server {
        listen 1995;
        content_by_lua_block {
            local s = ("123456789"):rep(1280)
            ngx.say(s)
        }
    }
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        math.randomseed(ngx.time())

        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        local dsk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(sk:connect("127.0.0.1", 1995))
        sk:settimeout(500)
        local total = 9 * 1280
        while total > 0 do
            local len = math.random(1, 512)
            if len > total then
                len = total
            end
            total = total - len
            if math.random(1, 2) == 1 then
                assert(sk:read(len))
            else
                assert(sk:drain(len))
            end
            if total % 2 == 0 then
                dsk:move(sk)
            end
        end
    }
--- stream_request
--- stream_response eval
"123456789" x 1280
--- timeout: 5
