use t::APISIX_NGINX 'no_plan';

run_tests;

__DATA__

=== TEST 1: global client_max_body_size set
--- config
    location /t {
				set $request_id 1234;
        apisix_request_id_var $request_id;
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_log eval
qr/log_msg.*request_id: "1234"$/
--- no_error_log
[error]
[crit]
[alert]
