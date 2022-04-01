use t::APISIX_NGINX 'no_plan';

run_tests();

__DATA__

=== TEST 1: read
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
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
                idx = idx + len
            end
        }
    }
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        local ffi = require("ffi")
        local sk = require("resty.apisix.stream.xrpc.socket").upstream.socket()
        assert(sk:connect("127.0.0.1", 1995))
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
--- stream_request
--- stream_response eval
"123456789" x 1024
