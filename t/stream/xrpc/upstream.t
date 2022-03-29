use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    my $stream_config = $block->stream_config;
    $stream_config .= <<'_EOC_';
    server {
        listen 1995;
        content_by_lua_block {
            local sk = ngx.req.socket(true)
            local resp = sk:receiveany(10240)
            ngx.log(ngx.WARN, "get resp data: ", resp)
            sk:send(resp)
        }
    }
_EOC_

    $block->set_value("stream_config", $stream_config);
});

run_tests();

__DATA__

=== TEST 1: inherit methods from raw socket
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
