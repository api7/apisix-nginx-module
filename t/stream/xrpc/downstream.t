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
