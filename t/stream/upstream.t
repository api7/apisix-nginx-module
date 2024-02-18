use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    server {
        listen 1994 ssl;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/mtls_server.crt;
        ssl_certificate_key ../../certs/mtls_server.key;

        location / {
            content_by_lua_block {
                ngx.say(ngx.var.ssl_server_name)
            }
        }
    }

_EOC_

        $block->set_value("http_config", $http_config);
    }
});

run_tests();

__DATA__

=== TEST 1: original upstream TLS proxying works
--- stream_server_config
    proxy_pass 127.0.0.1:1994;
    proxy_ssl on;
    proxy_ssl_server_name on;
    proxy_ssl_name admin.apisix.dev;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: admin.apisix.dev\r\n\r\n"
--- stream_response_like: ^HTTP/1.1 200 OK.*admin.apisix.dev



=== TEST 2: proxy TCP without TLS
--- stream_server_config
    proxy_pass 127.0.0.1:1994;
    proxy_ssl_server_name on;
    proxy_ssl_name admin.apisix.dev;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: admin.apisix.dev\r\n\r\n"
--- stream_response_like: ^.+400 The plain HTTP request was sent to HTTPS port.+$



=== TEST 3: proxy TCP over TLS
--- stream_server_config
    preread_by_lua_block {
        local up = require("resty.apisix.stream.upstream")
        up.set_tls()
    }
    proxy_pass 127.0.0.1:1994;
    proxy_ssl_server_name on;
    proxy_ssl_name admin.apisix.dev;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: admin.apisix.dev\r\n\r\n"
--- stream_response_like: ^HTTP/1.1 200 OK.*admin.apisix.dev