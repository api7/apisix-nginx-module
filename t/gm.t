use t::APISIX_NGINX;

my $openssl_version = eval { `openssl version 2>&1` };

if ($openssl_version !~ m/Tongsuo/) {
    plan(skip_all => "need Tongsuo");
} else {
    plan 'no_plan';
}

run_tests();

__DATA__

=== TEST 1: gm handshake
--- http_config
    lua_shared_dict done 16k;
    server {
        listen 1994 ssl;
        server_name   test.com;
        ssl_certificate_by_lua_block {
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

        }
        ssl_certificate ../../certs/apisix.crt;
        ssl_certificate_key ../../certs/apisix.key;

        server_tokens off;
        location / {
            content_by_lua_block {
                ngx.shared.done:set("handshake", true)
            }
        }
    }
--- config
    server_tokens off;

    location /t {
        content_by_lua_block {
            ngx.shared.done:delete("handshake")
            local req = "'GET / HTTP/1.0\r\nHost: test.com\r\nConnection: close\r\n\r\n'"
            local cmd = "./openssl s_client -connect 127.0.0.1:1994 " ..
                "-cipher ECDHE-SM2-WITH-SM4-SM3 -enable_ntls -ntls -verifyCAfile " ..
                "t/certs/gm_ca.crt -sign_cert t/certs/client_sign.crt -sign_key t/certs/client_sign.key " ..
                "-enc_cert t/certs/client_enc.crt -enc_key t/certs/client_enc.key"
            local f, err = io.popen("echo -n " .. req .. " | timeout 3s " .. cmd)
            if not f then
                ngx.say(err)
                return
            end

            local step = 0.001
            while step < 2 do
                ngx.sleep(step)
                step = step * 2

                if ngx.shared.done:get("handshake") then
                    local out = f:read('*a')
                    ngx.log(ngx.INFO, out)
                    ngx.say("ok")
                    f:close()
                    return
                end
            end

            ngx.log(ngx.ERR, "openssl client handshake timeout")
        }
    }

--- error_log
New, NTLSv1.1, Cipher is ECDHE-SM2-SM4-CBC-SM3
--- no_error_log
[error]
[alert]
[emerg]
