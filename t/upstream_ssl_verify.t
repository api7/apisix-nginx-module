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

        server_tokens off;

        location /tls {
            return 200 'ok\n';
        }
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx2.sock ssl;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/mtls_server.crt;
        ssl_certificate_key ../../certs/mtls_server.key;
        ssl_client_certificate ../../certs/mtls_ca.crt;
        ssl_verify_client on;

        server_tokens off;

        location /mtls {
            return 200 'ok\n';
        }
    }

_EOC_

        $block->set_value("http_config", $http_config);
    }
});

run_tests;

__DATA__


=== TEST 1: set ssl_verify with invalid ssl_name
--- FIRST
--- config
    location /t {
        access_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ok, err = upstream.set_ssl_verify(true)
            if not ok then
                ngx.log(ngx.ERR, "set_ssl_verify failed: ", err)
                ngx.exit(500)
            end
        }

        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/tls;
        proxy_ssl_name invalid.name;
    }
--- error_code: 502
--- error_log
upstream SSL certificate verify error: (20:unable to get local issuer certificate) while SSL handshaking to upstream



=== TEST 2: no ssl_verify with invalid ssl_name
--- config
    location /t {
        access_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ok, err = upstream.set_ssl_verify(false)
            if not ok then
                ngx.log(ngx.ERR, "set_ssl_verify failed: ", err)
                ngx.exit(500)
            end
        }

        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/tls;
        proxy_ssl_name invalid.name;
    }

--- response_body
ok



=== TEST 3: set ssl_verify
--- config
    location /t {
        access_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ok, err = upstream.set_ssl_verify(true)
            if not ok then
                ngx.log(ngx.ERR, "set_ssl_verify failed: ", err)
                ngx.exit(500)
            end
        }

        proxy_ssl_trusted_certificate ../../certs/mtls_ca.crt;
        proxy_ssl_verify on;
        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx.sock:/tls;
        proxy_ssl_name admin.apisix.dev;
    }

--- response_body
ok



=== TEST 4: invalid context
--- config
    location /t {
        content_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            upstream.set_ssl_verify(true)
        }
    }
--- error_code: 500
--- error_log
API disabled in the current context



=== TEST 5: invalid argument
--- config
    location /t {
        rewrite_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            ngx.status = 500
            local ok, _ = pcall(upstream.set_ssl_verify, 1)
            if not ok then
                ngx.say("invalid argument type: number")
            end
            
            local ok, _ = pcall(upstream.set_ssl_verify, "true")
            if not ok then
                ngx.say("invalid argument type: string")
            end

            local ok, err = pcall(upstream.set_ssl_verify, nil)
            if not ok then
                ngx.say("invalid argument type: nil")
            end

            local ok, err = pcall(upstream.set_ssl_verify, {})
            if not ok then
                ngx.say("invalid argument type: table")
            end
        }
    }
--- error_code: 500
--- response_body
invalid argument type: number
invalid argument type: string
invalid argument type: nil
invalid argument type: table



=== TEST 6: not verify upstream mtls certificate
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
                ngx.exit(500)
            end

            local ok, err = upstream.set_ssl_verify(false)
            if not ok then
                ngx.log(ngx.ERR, "set_ssl_verify failed: ", err)
                ngx.exit(500)
            end
        }

        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx2.sock:/mtls;
    }
--- error_code: 200
--- response_body
ok



=== TEST 7: set ssl_verify in upstream mtls, verified successfully
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

            f = assert(io.open("t/certs/mtls_ca.crt"))
            local ca_data = f:read("*a")
            f:close()

            local ca_cert = assert(ssl.parse_pem_cert(ca_data))

            local openssl_x509_store = require "resty.openssl.x509.store"
            local openssl_x509 = require "resty.openssl.x509"
            local trust_store, err = openssl_x509_store.new()
            if err then
                ngx.log(ngx.ERR, "failed to create trust store: ", err)
                ngx.exit(500)
            end

            local x509, err = openssl_x509.new(ca_data, "PEM")

            local _, err = trust_store:add(x509)
            if err then
                ngx.log(ngx.ERR, "failed to add ca cert to trust store: ", err)
                ngx.exit(500)
            end

            local ok, err = upstream.set_ssl_trusted_store(trust_store)
            if not ok then
                ngx.log(ngx.ERR, "set_ssl_trusted_store failed: ", err)
                ngx.exit(500)
            end

            local ok, err = upstream.set_ssl_verify(true)
            if not ok then
                ngx.log(ngx.ERR, "set_ssl_verify failed: ", err)
                ngx.exit(500)
            end
        }

        proxy_pass https://unix:$TEST_NGINX_HTML_DIR/nginx2.sock:/mtls;
        proxy_ssl_name admin.apisix.dev;
    }
--- response_body
ok
