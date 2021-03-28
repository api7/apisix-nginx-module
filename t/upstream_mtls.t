use t::APISIX_NGINX 'no_plan';

repeat_each(2);

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/mtls_server.crt;
        ssl_certificate_key ../../certs/mtls_server.key;
        ssl_client_certificate ../../certs/mtls_ca.crt;
        ssl_verify_client on;

        server_tokens off;

        location /foo {
            return 200 'ok\n';
        }
    }

_EOC_

        $block->set_value("http_config", $http_config);
    }
});

run_tests;

__DATA__

=== TEST 1: send client certificate
--- config
    location /t {
        access_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ssl = require("ngx.ssl")

            local f = assert(io.open("t/certs/mtls_client.crt"))
            local cert_data = f:read("*a")
            f:close()

            local cert = assert(ssl.parse_pem_cert(cert_data))

            f = assert(io.open("t/certs/mtls_client.key"))
            local key_data = f:read("*a")
            f:close()

            local key = assert(ssl.parse_pem_priv_key(key_data))

            local ok, err = upstream.set_cert_and_key(cert, key)
            if not ok then
                ngx.say("set_cert_and_key failed: ", err)
            end
        }

        proxy_ssl_trusted_certificate ../../certs/mtls_ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_name admin.apisix.dev;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- response_body
ok



=== TEST 2: send bad client certificate
--- config
    location /t {
        access_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ssl = require("ngx.ssl")

            local f = assert(io.open("t/certs/mtls_client.crt"))
            local cert_data = f:read("*a")
            f:close()

            local cert = assert(ssl.parse_pem_cert(cert_data))

            f = assert(io.open("t/certs/mtls_client.key"))
            local key_data = f:read("*a")
            f:close()

            local ok, err = upstream.set_cert_and_key(cert, nil)
            if not ok then
                ngx.say("set_cert_and_key failed: ", err)
            end
        }

        proxy_ssl_trusted_certificate ../../certs/mtls_ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_name admin.apisix.dev;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- response_body
set_cert_and_key failed: both client certificate and private key should be given



=== TEST 3: send wrong client certificate
--- config
    location /t {
        access_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ssl = require("ngx.ssl")

            local f = assert(io.open("t/certs/apisix.crt"))
            local cert_data = f:read("*a")
            f:close()

            local cert = assert(ssl.parse_pem_cert(cert_data))

            f = assert(io.open("t/certs/apisix.key"))
            local key_data = f:read("*a")
            f:close()

            local key = assert(ssl.parse_pem_priv_key(key_data))

            local ok, err = upstream.set_cert_and_key(cert, key)
            if not ok then
                ngx.say("set_cert_and_key failed: ", err)
            end
        }

        proxy_ssl_trusted_certificate ../../certs/mtls_ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_name admin.apisix.dev;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- error_code: 400
--- error_log
client SSL certificate verify error



=== TEST 4: call set_cert_and_key repeatedly
--- config
    location /t {
        access_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ssl = require("ngx.ssl")

            local f = assert(io.open("t/certs/mtls_client.crt"))
            local cert_data = f:read("*a")
            f:close()

            local cert = assert(ssl.parse_pem_cert(cert_data))

            f = assert(io.open("t/certs/mtls_client.key"))
            local key_data = f:read("*a")
            f:close()

            local key = assert(ssl.parse_pem_priv_key(key_data))

            for i = 1, 5 do
                local ok, err = upstream.set_cert_and_key(cert, key)
                if not ok then
                    ngx.say("set_cert_and_key failed: ", err)
                end
            end
        }

        proxy_ssl_trusted_certificate ../../certs/mtls_ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_name admin.apisix.dev;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/foo;
    }

--- response_body
ok
