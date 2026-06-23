use t::APISIX_NGINX 'no_plan';

repeat_each(2);

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    server {
        listen 1995 ssl;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/mtls_server.crt;
        ssl_certificate_key ../../certs/mtls_server.key;
        ssl_client_certificate ../../certs/mtls_ca.crt;
        ssl_verify_client on;

        server_tokens off;

        location / {
            content_by_lua_block {
                ngx.say("client verify: ", ngx.var.ssl_client_verify)
            }
        }
    }

_EOC_

        $block->set_value("http_config", $http_config);
    }
});

run_tests();

__DATA__

=== TEST 1: stream upstream mTLS - send client cert and key, handshake succeeds
--- stream_server_config
    preread_by_lua_block {
        local up = require("resty.apisix.stream.upstream")
        local ssl = require("ngx.ssl")

        local f = assert(io.open("t/certs/mtls_client.crt"))
        local cert_data = f:read("*a")
        f:close()
        local cert = assert(ssl.parse_pem_cert(cert_data))

        f = assert(io.open("t/certs/mtls_client.key"))
        local key_data = f:read("*a")
        f:close()
        local key = assert(ssl.parse_pem_priv_key(key_data))

        assert(up.set_tls())
        assert(up.set_cert_and_key(cert, key))
    }
    proxy_pass 127.0.0.1:1995;
    proxy_ssl_server_name on;
    proxy_ssl_name admin.apisix.dev;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: admin.apisix.dev\r\n\r\n"
--- stream_response_like: client verify: SUCCESS



=== TEST 2: missing private key is rejected before the handshake
--- stream_server_config
    preread_by_lua_block {
        local up = require("resty.apisix.stream.upstream")
        local ssl = require("ngx.ssl")

        local f = assert(io.open("t/certs/mtls_client.crt"))
        local cert_data = f:read("*a")
        f:close()
        local cert = assert(ssl.parse_pem_cert(cert_data))

        assert(up.set_tls())
        local ok, err = up.set_cert_and_key(cert, nil)
        if not ok then
            ngx.log(ngx.ERR, "set_cert_and_key failed: ", err)
        end
    }
    proxy_pass 127.0.0.1:1995;
    proxy_ssl_server_name on;
    proxy_ssl_name admin.apisix.dev;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: admin.apisix.dev\r\n\r\n"
--- error_log
set_cert_and_key failed: both client certificate and private key should be given
--- stream_response_like: No required SSL certificate was sent



=== TEST 3: wrong client certificate is rejected by the upstream
--- stream_server_config
    preread_by_lua_block {
        local up = require("resty.apisix.stream.upstream")
        local ssl = require("ngx.ssl")

        -- apisix.crt is not signed by mtls_ca.crt, so the upstream rejects it
        local f = assert(io.open("t/certs/apisix.crt"))
        local cert_data = f:read("*a")
        f:close()
        local cert = assert(ssl.parse_pem_cert(cert_data))

        f = assert(io.open("t/certs/apisix.key"))
        local key_data = f:read("*a")
        f:close()
        local key = assert(ssl.parse_pem_priv_key(key_data))

        assert(up.set_tls())
        assert(up.set_cert_and_key(cert, key))
    }
    proxy_pass 127.0.0.1:1995;
    proxy_ssl_server_name on;
    proxy_ssl_name admin.apisix.dev;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: admin.apisix.dev\r\n\r\n"
--- error_log
client SSL certificate verify error



=== TEST 4: set_cert_and_key called repeatedly still handshakes
--- stream_server_config
    preread_by_lua_block {
        local up = require("resty.apisix.stream.upstream")
        local ssl = require("ngx.ssl")

        local f = assert(io.open("t/certs/mtls_client.crt"))
        local cert_data = f:read("*a")
        f:close()
        local cert = assert(ssl.parse_pem_cert(cert_data))

        f = assert(io.open("t/certs/mtls_client.key"))
        local key_data = f:read("*a")
        f:close()
        local key = assert(ssl.parse_pem_priv_key(key_data))

        assert(up.set_tls())
        for _ = 1, 5 do
            assert(up.set_cert_and_key(cert, key))
        end
    }
    proxy_pass 127.0.0.1:1995;
    proxy_ssl_server_name on;
    proxy_ssl_name admin.apisix.dev;
--- stream_request eval
"GET / HTTP/1.0\r\nHost: admin.apisix.dev\r\n\r\n"
--- stream_response_like: client verify: SUCCESS
