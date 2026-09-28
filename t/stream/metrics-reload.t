BEGIN {
    # the zone is only reused across a reload, which is what these cases need
    $ENV{TEST_NGINX_USE_HUP} = 1;
}

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
});

run_tests();

__DATA__

=== TEST 1: fill the zone with labels
--- stream_config
apisix_stream_metrics_zone 32k;
--- stream_server_config
    preread_by_lua_block {
        local metrics = require("resty.apisix.stream.metrics")
        for i = 1, 1000 do
            local ok, err = metrics.set_labels({"svc-" .. i})
            if not ok then
                ngx.log(ngx.WARN, "labels stopped: ", err)
                break
            end
        end
    }
    proxy_pass 127.0.0.1:1994;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
--- stream_response_like: hello
--- error_log
labels stopped: stream metrics zone is full



=== TEST 2: a listening address added by a reload still gets a slot
Labels cannot take the share of the zone kept for listening addresses, so the
one this reload adds is still counted, next to the labels the zone kept.
--- stream_config
apisix_stream_metrics_zone 32k;

server {
    listen 127.0.0.1:1986;
    proxy_pass 127.0.0.1:1994;
}
--- stream_server_config
    proxy_pass 127.0.0.1:1994;
--- config
    location /probe {
        content_by_lua_block {
            local metrics = require("resty.apisix.stream.metrics")

            local sock = ngx.socket.tcp()
            assert(sock:connect("127.0.0.1", 1986))
            assert(sock:send("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"))
            assert(sock:receive("*a"))
            assert(sock:close())
            ngx.sleep(0.3)

            local labelled = 0
            for _, e in ipairs(assert(metrics.dump())) do
                if e.listen_addr == "127.0.0.1:1986" then
                    ngx.say("new listen di=", e.downstream_ingress,
                            " labels=", #e.labels)
                elseif #e.labels > 0 then
                    labelled = labelled + 1
                end
            end

            ngx.say("labels kept: ", labelled > 0)
        }
    }
--- request
GET /probe
--- response_body
new listen di=35 labels=0
labels kept: true
--- no_error_log
[error]
