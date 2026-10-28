use t::APISIX_NGINX 'no_plan';

repeat_each(1);

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    server {
        listen unix:$TEST_NGINX_HTML_DIR/good.sock ssl http2;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/crl_server.crt;
        ssl_certificate_key ../../certs/crl_server.key;

        server_tokens off;

        location / {
            return 200 'ok\n';
        }
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/revoked.sock ssl http2;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/crl_revoked.crt;
        ssl_certificate_key ../../certs/crl_revoked.key;

        server_tokens off;

        location / {
            return 200 'ok\n';
        }
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/untrusted.sock ssl http2;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/mtls_server.crt;
        ssl_certificate_key ../../certs/mtls_server.key;

        server_tokens off;

        location / {
            return 200 'ok\n';
        }
    }

    proxy_ssl_trusted_certificate ../../certs/crl_ca.crt;
    proxy_ssl_crl ../../certs/crl_ca.crl;
    proxy_ssl_name admin.apisix.dev;

    grpc_ssl_trusted_certificate ../../certs/crl_ca.crt;
    grpc_ssl_crl ../../certs/crl_ca.crl;
    grpc_ssl_name admin.apisix.dev;
_EOC_

        $block->set_value("http_config", $http_config);
    }

    if (!$block->request) {
        $block->set_value("request", "GET /t");
    }
});

run_tests;

__DATA__

=== TEST 1: proxy, verify per request, trusted certificate
--- config
    location /t {
        access_by_lua_block {
            assert(require("resty.apisix.upstream").set_ssl_verify(true))
        }
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/good.sock:/;
    }
--- response_body
ok



=== TEST 2: proxy, verify per request, revoked certificate
--- config
    location /t {
        access_by_lua_block {
            assert(require("resty.apisix.upstream").set_ssl_verify(true))
        }
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/revoked.sock:/;
    }
--- error_code: 502
--- error_log
upstream SSL certificate verify error: (23:certificate revoked) while SSL handshaking to upstream



=== TEST 3: proxy, verify per request, untrusted certificate
--- config
    location /t {
        access_by_lua_block {
            assert(require("resty.apisix.upstream").set_ssl_verify(true))
        }
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/untrusted.sock:/;
    }
--- error_code: 502
--- error_log eval
qr/upstream SSL certificate verify error: \(2[01]:unable to (get local issuer certificate|verify the first certificate)\) while SSL handshaking to upstream/



=== TEST 4: proxy, loading the trusted certificates does not enable verification
--- config
    location /t {
        content_by_lua_block {
            for _, name in ipairs({"good", "revoked", "untrusted"}) do
                local res = ngx.location.capture("/" .. name)
                ngx.say(name, ": ", res.status)
            end
        }
    }
    location ~ ^/(good|revoked|untrusted)$ {
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/$1.sock:/;
    }
--- response_body
good: 200
revoked: 200
untrusted: 200



=== TEST 5: proxy, static verify, trusted certificate
--- config
    location /t {
        proxy_ssl_verify on;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/good.sock:/;
    }
--- response_body
ok



=== TEST 6: proxy, static verify, revoked certificate
--- config
    location /t {
        proxy_ssl_verify on;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/revoked.sock:/;
    }
--- error_code: 502
--- error_log
upstream SSL certificate verify error: (23:certificate revoked) while SSL handshaking to upstream



=== TEST 7: proxy, static verify disabled per request
--- config
    location /t {
        access_by_lua_block {
            assert(require("resty.apisix.upstream").set_ssl_verify(false))
        }
        proxy_ssl_verify on;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/untrusted.sock:/;
    }
--- response_body
ok



=== TEST 8: grpc, verify per request, trusted certificate
--- config
    location /t {
        access_by_lua_block {
            assert(require("resty.apisix.upstream").set_ssl_verify(true))
        }
        grpc_pass grpcs://unix:$TEST_NGINX_HTML_DIR/good.sock;
    }
--- response_body
ok



=== TEST 9: grpc, verify per request, revoked certificate
--- config
    location /t {
        access_by_lua_block {
            assert(require("resty.apisix.upstream").set_ssl_verify(true))
        }
        grpc_pass grpcs://unix:$TEST_NGINX_HTML_DIR/revoked.sock;
    }
--- error_code: 502
--- error_log
upstream SSL certificate verify error: (23:certificate revoked) while SSL handshaking to upstream



=== TEST 10: grpc, verify per request, untrusted certificate
--- config
    location /t {
        access_by_lua_block {
            assert(require("resty.apisix.upstream").set_ssl_verify(true))
        }
        grpc_pass grpcs://unix:$TEST_NGINX_HTML_DIR/untrusted.sock;
    }
--- error_code: 502
--- error_log eval
qr/upstream SSL certificate verify error: \(2[01]:unable to (get local issuer certificate|verify the first certificate)\) while SSL handshaking to upstream/



=== TEST 11: grpc, loading the trusted certificates does not enable verification
--- config
    location /t {
        content_by_lua_block {
            for _, name in ipairs({"good", "revoked", "untrusted"}) do
                local res = ngx.location.capture("/" .. name)
                ngx.say(name, ": ", res.status)
            end
        }
    }
    location ~ ^/(good|revoked|untrusted)$ {
        grpc_pass grpcs://unix:$TEST_NGINX_HTML_DIR/$1.sock;
    }
--- response_body
good: 200
revoked: 200
untrusted: 200



=== TEST 12: grpc, static verify, trusted certificate
--- config
    location /t {
        grpc_ssl_verify on;
        grpc_pass grpcs://unix:$TEST_NGINX_HTML_DIR/good.sock;
    }
--- response_body
ok



=== TEST 13: grpc, static verify, revoked certificate
--- config
    location /t {
        grpc_ssl_verify on;
        grpc_pass grpcs://unix:$TEST_NGINX_HTML_DIR/revoked.sock;
    }
--- error_code: 502
--- error_log
upstream SSL certificate verify error: (23:certificate revoked) while SSL handshaking to upstream



=== TEST 14: static verify still requires trusted certificates
--- http_config
    # no proxy_ssl_trusted_certificate
--- config
    location /t {
        proxy_ssl_verify on;
        proxy_pass https://127.0.0.1:1;
    }
--- must_die
--- error_log
no proxy_ssl_trusted_certificate for proxy_ssl_verify
