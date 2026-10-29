use t::APISIX_NGINX 'no_plan';

run_tests();

__DATA__

=== TEST 1: session_hostname before the session exists (http subsystem)
--- skip_nginx
3: < 1.31.8
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/ssl.sock ssl;
        server_name test.com;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        ssl_client_hello_by_lua_block {
            local name, err = require("ngx.ssl").session_hostname()
            ngx.log(ngx.WARN, "session_hostname: ", name, ", err: ", err)
        }

        location / {
            return 200;
        }
    }
--- config
    location = /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/ssl.sock"))
            local ok, err = sock:sslhandshake(nil, "test.com", false)
            ngx.say("handshake: ", ok and "ok" or err)
        }
    }
--- response_body
handshake: ok
--- error_log
session_hostname: nil, err: nil



=== TEST 2: session_hostname before the session exists (stream subsystem)
--- skip_nginx
3: < 1.31.8
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/stream_ssl.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        ssl_client_hello_by_lua_block {
            local name, err = require("ngx.ssl").session_hostname()
            ngx.log(ngx.WARN, "session_hostname: ", name, ", err: ", err)
        }
        content_by_lua_block {
            ngx.say("ok")
        }
    }
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/stream_ssl.sock"))
        local ok, err = sock:sslhandshake(nil, "test.com", false)
        ngx.say("handshake: ", ok and "ok" or err)
    }
--- stream_request
--- stream_response
handshake: ok
--- error_log
session_hostname: nil, err: nil
