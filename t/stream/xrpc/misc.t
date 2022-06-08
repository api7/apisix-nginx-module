use t::APISIX_NGINX 'no_plan';

run_tests();

__DATA__

=== TEST 1: has_pending_data
--- stream_server_config
    content_by_lua_block {
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        local p, err, len = sk:read_line(128)
        if err then
            ngx.say(err)
            return
        end
        ngx.say(sk:has_pending_data())
    }
--- stream_request eval
"hello world\r\n" x 2
--- stream_response
true



=== TEST 2: has_pending_data, all are read
--- stream_server_config
    content_by_lua_block {
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        local p, err, len = sk:read_line(128)
        if err then
            ngx.say(err)
            return
        end
        ngx.say(sk:has_pending_data())
    }
--- stream_request eval
"hello world\r\n"
--- stream_response
false



=== TEST 3: has_pending_data, multiple read
--- stream_server_config
    content_by_lua_block {
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(sk:read(4))
        assert(sk:drain(7))
        ngx.say(sk:has_pending_data())
    }
--- stream_request eval
"hello world"
--- stream_response
false



=== TEST 4: has_pending_data, buffer is greater than lua_socket_buffer_size
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        assert(sk:read(132))
        -- In this case, the has_pending_data has to return true as
        -- there is no way to know if there is pending data without a read
        ngx.say(sk:has_pending_data())
    }
--- stream_request eval
"1234" x 33
--- stream_response
true
