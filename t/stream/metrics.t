use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    server {
        listen 1994;

        location / {
            content_by_lua_block {
                ngx.print("hello")
            }
        }
    }

_EOC_

        $block->set_value("http_config", $http_config);
    }

    # blocks that need to run without a zone set stream_config themselves
    if (defined $block->stream_server_config && !defined $block->stream_config) {
        $block->set_value("stream_config", "apisix_stream_metrics_zone 1m;\n");
    }
});

run_tests();

__DATA__

=== TEST 1: a session closed by the upstream is reported as a normal close
--- stream_server_config
    proxy_pass 127.0.0.1:1994;
    log_by_lua_block {
        ngx.log(ngx.WARN, "reason: ", ngx.var.stream_session_reason,
                ", listen: ", ngx.var.stream_listen_addr)
    }
--- stream_request eval
"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
--- stream_response_like: hello
--- error_log eval
qr/reason: closed, listen: [\d.]+:\d+/



=== TEST 2: an idle session is reported as a receive timeout, not as 200/closed
--- stream_server_config
    proxy_timeout 100ms;
    proxy_pass 127.0.0.1:1994;
    log_by_lua_block {
        ngx.log(ngx.WARN, "reason: ", ngx.var.stream_session_reason,
                ", status: ", ngx.var.status)
    }
--- stream_request eval
"GET /"
--- timeout: 5
--- wait: 0.5
--- error_log
reason: recv_timeout, status: 200



=== TEST 3: an unreachable upstream keeps the native 502
--- stream_server_config
    proxy_connect_timeout 300ms;
    proxy_pass 127.0.0.1:1979;
    log_by_lua_block {
        ngx.log(ngx.WARN, "status: ", ngx.var.status)
    }
--- stream_request eval
"GET /"
--- error_log
status: 502



=== TEST 4: bytes are accounted per listening address in both directions
--- stream_server_config
    proxy_pass 127.0.0.1:1994;
    log_by_lua_block {
        local metrics = require("resty.apisix.stream.metrics")
        local res, err = metrics.dump()
        if not res then
            ngx.log(ngx.ERR, "dump failed: ", err)
            return
        end

        for _, e in ipairs(res) do
            ngx.log(ngx.WARN, "slot ", e.listen_addr,
                    " active=", e.active,
                    " di=", e.downstream_ingress > 0,
                    " de=", e.downstream_egress > 0,
                    " ue=", e.upstream_egress > 0,
                    " ui=", e.upstream_ingress > 0)
        end
    }
--- stream_request eval
"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
--- stream_response_like: hello
--- error_log
active=1 di=true de=true ue=true ui=true



=== TEST 5: the FFI reader reports a missing zone instead of returning garbage
--- stream_config
# intentionally no apisix_stream_metrics_zone here
--- stream_server_config
    proxy_pass 127.0.0.1:1994;
    log_by_lua_block {
        local metrics = require("resty.apisix.stream.metrics")
        local res, err = metrics.dump()
        ngx.log(ngx.WARN, "dump: ", res, " err: ", err)
    }
--- stream_request eval
"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
--- stream_response_like: hello
--- error_log
dump: nil err: stream metrics zone is not configured



=== TEST 6: $stream_session_reason still works without a metrics zone
--- stream_config
# intentionally no apisix_stream_metrics_zone here
--- stream_server_config
    proxy_pass 127.0.0.1:1994;
    log_by_lua_block {
        ngx.log(ngx.WARN, "reason: ", ngx.var.stream_session_reason)
    }
--- stream_request eval
"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
--- stream_response_like: hello
--- error_log
reason: closed
