use t::APISIX_NGINX 'no_plan';

our $HttpConfig = <<_EOC_;
    init_by_lua_block {
        local ssl = require("ngx.ssl")
        local openssl_x509 = require("resty.openssl.x509")
        local openssl_x509_store = require("resty.openssl.x509.store")

        local function read(path)
            local f = assert(io.open(path))
            local data = f:read("*a")
            f:close()
            return data
        end

        local function new_store(path)
            local store = assert(openssl_x509_store.new())
            assert(store:add(assert(openssl_x509.new(read(path), "PEM"))))
            return store
        end

        package.loaded.helper = {
            cert = assert(ssl.parse_pem_cert(read("t/certs/mtls_client.crt"))),
            key = assert(ssl.parse_pem_priv_key(read("t/certs/mtls_client.key"))),
            good_store = new_store("t/certs/mtls_ca.crt"),
            bad_store = new_store("t/certs/test.crt"),
        }
    }

    upstream lua_backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            local b = require("ngx.balancer")
            assert(b.set_current_peer("127.0.0.1", $ENV{TEST_NGINX_SERVER_SSL_PORT}))
            assert(b.enable_keepalive())
        }
    }

    server {
        listen 127.0.0.1:$ENV{TEST_NGINX_SERVER_SSL_PORT} ssl;
        server_name admin.apisix.dev;
        ssl_certificate ../../certs/mtls_server.crt;
        ssl_certificate_key ../../certs/mtls_server.key;
        ssl_client_certificate ../../certs/mtls_ca.crt;
        ssl_verify_client optional;

        location /dn {
            return 200 'dn=\$ssl_client_s_dn requests=\$connection_requests\\n';
        }
    }
_EOC_

our $Config = <<'_EOC_';
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_ssl_session_reuse off;
    proxy_ssl_name admin.apisix.dev;

    location /plain {
        proxy_pass https://lua_backend/dn;
    }

    location /plain_verified {
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate ../../certs/mtls_ca.crt;
        proxy_pass https://lua_backend/dn;
    }

    location /cert {
        access_by_lua_block {
            local h = require("helper")
            assert(require("resty.apisix.upstream").set_cert_and_key(h.cert, h.key))
        }
        proxy_pass https://lua_backend/dn;
    }

    location /store_good {
        access_by_lua_block {
            local h = require("helper")
            assert(require("resty.apisix.upstream").set_ssl_trusted_store(h.good_store))
        }
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate ../../certs/test.crt;
        proxy_pass https://lua_backend/dn;
    }

    location /store_bad {
        access_by_lua_block {
            local h = require("helper")
            assert(require("resty.apisix.upstream").set_ssl_trusted_store(h.bad_store))
        }
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate ../../certs/mtls_ca.crt;
        proxy_pass https://lua_backend/dn;
    }

    location /verify {
        access_by_lua_block {
            assert(require("resty.apisix.upstream").set_ssl_verify(true))
        }
        proxy_ssl_trusted_certificate ../../certs/test.crt;
        proxy_pass https://lua_backend/dn;
    }
_EOC_

add_block_preprocessor(sub {
    my $block = shift;

    $block->set_value("http_config", $HttpConfig);
    $block->set_value("config", $Config);

    if (!defined $block->skip_nginx) {
        $block->set_value("skip_nginx", "3: < 1.31.1");
    }
});

run_tests();

__DATA__

=== TEST 1: a client certificate gets its own Lua pool
--- request eval
["GET /plain", "GET /cert", "GET /plain"]
--- response_body eval
["dn= requests=1\n",
 "dn=CN=client.apisix.dev,L=ZhuHai,O=api7,ST=GuangDong,C=cn requests=1\n",
 "dn= requests=2\n"]



=== TEST 2: a plain request skips the pooled client certificate connection
--- request eval
["GET /cert", "GET /plain"]
--- response_body eval
["dn=CN=client.apisix.dev,L=ZhuHai,O=api7,ST=GuangDong,C=cn requests=1\n",
 "dn= requests=1\n"]



=== TEST 3: the same client certificate reuses its connection
--- request eval
["GET /cert", "GET /cert"]
--- response_body eval
["dn=CN=client.apisix.dev,L=ZhuHai,O=api7,ST=GuangDong,C=cn requests=1\n",
 "dn=CN=client.apisix.dev,L=ZhuHai,O=api7,ST=GuangDong,C=cn requests=2\n"]



=== TEST 4: a trusted store verifies on a new connection
--- request eval
["GET /plain_verified", "GET /store_bad"]
--- error_code eval
[200, 502]
--- response_body_like eval
["dn= requests=1\n", "502 Bad Gateway"]
--- no_error_log
[alert]



=== TEST 5: the same trusted store reuses its connection
--- request eval
["GET /plain", "GET /store_good", "GET /store_good"]
--- response_body eval
["dn= requests=1\n", "dn= requests=1\n", "dn= requests=2\n"]



=== TEST 6: a per-request verify flag verifies on a new connection
--- request eval
["GET /plain", "GET /verify"]
--- error_code eval
[200, 502]
--- response_body_like eval
["dn= requests=1\n", "502 Bad Gateway"]
--- no_error_log
[alert]
