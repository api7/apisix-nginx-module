use t::APISIX_NGINX 'no_plan';

run_tests;

__DATA__

=== TEST 1: proxy_request_buffering off
--- config
    proxy_request_buffering off;
    location /t {
        proxy_pass http://127.0.0.1:1984/up;
    }
    location /up {
        return 200;
    }
--- request eval
"POST /t
" . "12345" x 10240
--- grep_error_log eval
qr/a client request body is buffered to a temporary file/
--- grep_error_log_out



=== TEST 2: proxy_request_buffering off by Lua API
--- config
    proxy_request_buffering on;
    location /t {
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_proxy_request_buffering(false))
        }
        proxy_pass http://127.0.0.1:1984/up;
    }
    location /up {
        return 200;
    }
--- request eval
"POST /t
" . "12345" x 10240
--- grep_error_log eval
qr/a client request body is buffered to a temporary file/
--- grep_error_log_out



=== TEST 3: proxy_request_buffering on
--- config
    proxy_request_buffering on;
    location /t {
        proxy_pass http://127.0.0.1:1984/up;
    }
    location /up {
        return 200;
    }
--- request eval
"POST /t
" . "12345" x 10240
--- grep_error_log eval
qr/a client request body is buffered to a temporary file/
--- grep_error_log_out
a client request body is buffered to a temporary file



=== TEST 4: proxy_request_buffering on by Lua API
--- config
    proxy_request_buffering off;
    location /t {
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_proxy_request_buffering(true))
        }
        proxy_pass http://127.0.0.1:1984/up;
    }
    location /up {
        return 200;
    }
--- request eval
"POST /t
" . "12345" x 10240
--- grep_error_log eval
qr/a client request body is buffered to a temporary file/
--- grep_error_log_out
a client request body is buffered to a temporary file
