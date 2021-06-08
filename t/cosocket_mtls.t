use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/mtls_server.crt;
        ssl_certificate_key ../../certs/mtls_server.key;
        ssl_client_certificate ../../certs/mtls_server.crt;
        ssl_verify_client on;

        location / {
            return 200 'ok\n';
        }
    }

_EOC_

        $block->set_value("http_config", $http_config);
    }
});

run_tests;

__DATA__

=== TEST 1: avoid using stale openssl error code
--- config
    location /t {
        access_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            for i = 1, 2 do
                local ok, err = sock:tlshandshake({
                    verify = true,
                    client_cert_path = "t/certs/mtls_client.crt",
                    client_priv_key_path = "t/certs/mtls_client.key",
                })
                if not ok then
                    ngx.say(err)
                end
            end
        }
    }
--- response_body
20: unable to get local issuer certificate
closed
--- error_log
[error]
