use t::APISIX_NGINX;

my $openssl_version = eval { `/export/servers/tongsuo_jfe/bin/openssl version 2>&1` };
if ($openssl_version !~ m/Tongsuo/) {
    plan(skip_all => "need Tongsuo");
} else {
    plan 'no_plan';
}


add_block_preprocessor(sub {
    my ($block) = @_;

    my $stream_config = $block->stream_config // '';
    $stream_config .= <<_EOC_;
    init_by_lua_block {
        function set_gm_cert_and_key()
            local ngx_ssl = require "ngx.ssl"
            local ssl = require "resty.apisix.ssl"

            ngx_ssl.clear_certs()

            local f = assert(io.open("t/certs/server_enc.crt"))
            local cert_enc = f:read("*a")
            f:close()

            local cert_enc, err = ngx_ssl.parse_pem_cert(cert_enc)
            if not cert_enc then
                ngx.log(ngx.ERR, "failed to parse pem cert: ", err)
                return
            end

            local f = assert(io.open("t/certs/server_sign.crt"))
            local cert_sign = f:read("*a")
            f:close()

            local cert_sign, err = ngx_ssl.parse_pem_cert(cert_sign)
            if not cert_enc then
                ngx.log(ngx.ERR, "failed to parse pem cert: ", err)
                return
            end

            local ok, err = ssl.set_gm_cert(cert_enc, cert_sign)
            if not ok then
                ngx.log(ngx.ERR, "failed to set cert: ", err)
                return
            end

            local f = assert(io.open("t/certs/server_enc.key"))
            local pkey_data = f:read("*a")
            f:close()

            local pkey_enc, err = ngx_ssl.parse_pem_priv_key(pkey_data)
            if not pkey_enc then
                ngx.log(ngx.ERR, "failed to parse pem key: ", err)
                return
            end

            local f = assert(io.open("t/certs/server_sign.key"))
            local pkey_data = f:read("*a")
            f:close()

            local pkey_sign, err = ngx_ssl.parse_pem_priv_key(pkey_data)
            if not pkey_sign then
                ngx.log(ngx.ERR, "failed to parse pem key: ", err)
                return
            end

            local ok, err = ssl.set_gm_priv_key(pkey_enc, pkey_sign)
            if not ok then
                ngx.log(ngx.ERR, "failed to set private key: ", err)
                return
            end
            ngx.log(ngx.WARN, "====set_gm_cert_and_key done==")
        end
    }
_EOC_

    $block->set_value("stream_config", $stream_config);

    my $http_config = $block->http_config // '';
    $http_config .= <<_EOC_;
    init_by_lua_block {
        function handshake()
            local req = "'ping\\r\\n'"
            --[[
            local cmd = "/export/servers/tongsuo_jfe/bin/openssl s_client -connect 127.0.0.1:1986 " ..
                "-enable_ntls -ntls -verifyCAfile t/certs/gm_ca.crt"
            --]]
            local cmd = "/export/servers/tongsuo_jfe/bin/openssl s_client -connect 127.0.0.1:1986 " ..
                "-cipher ECDHE-SM2-WITH-SM4-SM3 -enable_ntls -ntls -verifyCAfile " ..
                "t/certs/gm_ca.crt -sign_cert t/certs/client_sign.crt -sign_key t/certs/client_sign.key " ..
                "-enc_cert t/certs/client_enc.crt -enc_key t/certs/client_enc.key"
            return io.popen("echo -n " .. req .. " | timeout 3s " .. cmd)
        end
    }
_EOC_

    $block->set_value("http_config", $http_config);
});

run_tests();

__DATA__

=== TEST 1: gm handshake
--- stream_config
    init_worker_by_lua_block {
        local ssl = require "resty.apisix.ssl"
        ssl.enable_ntls()
    }

    server {
        listen 1986 ssl;

        ssl_certificate_by_lua_block {
            set_gm_cert_and_key()
        }
        ssl_certificate ../../certs/apisix.crt;
        ssl_certificate_key ../../certs/apisix.key;

        content_by_lua_block {
            ngx.say("PONG")
        }
    }

--- stream_server_config
        content_by_lua_block {
            ngx.say("OK")
        }

--- config
    server_tokens off;

    location /test {
        content_by_lua_block {
            local f, err = handshake()
            ngx.log(ngx.INFO, "===call handshake==")
            if not f then
                ngx.say(err)
                return
            end
            ngx.sleep(5)
            ngx.log(ngx.INFO, "===read handshake==")            
            local out = f:read('*a')
            ngx.log(ngx.INFO, "===out==", out)
            ngx.say("ok")
            f:close()
            return
        }
    }

--- request
GET /test
--- timeout: 10s
--- error_log_like
New, NTLSv1.1, Cipher is *-SM2-SM4-*-SM3
--- no_error_log
[error]
[alert]
[emerg]