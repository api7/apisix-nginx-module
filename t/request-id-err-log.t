use t::APISIX_NGINX 'no_plan';

run_tests;

__DATA__

=== TEST 1: request_id in error log set
--- config
    location /t {
		set $request_id_new 1234;
        apisix_request_id_var $request_id_new;
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /t
--- error_log eval
qr/log_msg.*request_id: "1234"$/
--- no_error_log
[error]
[crit]
[alert]



=== TEST 2: request_id in error log set when a runtime error occurs
--- config
    location /t {
		set $request_id_new 1234;
        apisix_request_id_var $request_id_new;
        content_by_lua_block {
            error("error_message")
        }
    }
--- request
GET /t
--- error_code: 500
--- error_log eval
qr/.*request_id: "1234".*$/



=== TEST 3: scoping: value is appended correctly to error logs
based on the location where the directive is defined
--- config
    location /append_req_id {
        set $req_id_a 123456;
        apisix_request_id_var $req_id_a;
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
    location /append_method {
        set $req_id_b 654321;
        apisix_request_id_var $req_id_b;

        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- pipelined_requests eval
["GET /append_req_id", "GET /append_method"]
--- error_code eval
[200, 200, 200]
--- error_log eval
[ 'request_id: "123456"', 'request_id: "654321"' ]
--- no_error_log
[error]
[crit]
[alert]



=== TEST 4: scoping: value is NOT appended to error logs for the location where the directive is NOT defined
--- config
    location /append {
        set $req_id 123456;
        apisix_request_id_var $req_id;
        content_by_lua_block {
            ngx.log(ngx.ERR, "log_msg")
            ngx.exit(200)
        }
    }
    location /no_append {
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /no_append
--- error_code: 200
--- no_error_log eval
qr/log_msg.*request_id/



=== TEST 5: scoping: value is appended correctly to error logs when the directive is in the main configuration
--- http_config
    apisix_request_id_var $req_id;
--- config
    set $req_id 123456;
    location = /test {
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
qr/log_msg.*request_id: "123456"$/
--- no_error_log
[error]
[crit]
[alert]



=== TEST 6: scoping: value is appended correctly to error logs and the local directive overrides the global one
--- http_config
    apisix_request_id_var $req_id_global;
--- config
    set $req_id_global global;
    set $req_id_local local;

    location = /test {
        apisix_request_id_var $req_id_local;
        content_by_lua_block {
            ngx.log(ngx.INFO, "log_msg")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_code: 200
--- error_log eval
qr/log_msg.*request_id: "local"$/
--- no_error_log eval
qr/log_msg.*request_id: "global"$/



=== TEST 7: Request ID variable changes are applied to the error log output
--- config
    location = /test {
        set $my_var "";
        apisix_request_id_var $my_var;
        rewrite_by_lua_block {
            ngx.log(ngx.INFO, "rewrite_0")
            ngx.var.my_var = "changed_in_rewrite"
            ngx.log(ngx.INFO, "rewrite_1")
            ngx.var.my_var = "changed_in_rewrite_2"
            ngx.log(ngx.INFO, "rewrite_2")
        }
        access_by_lua_block {
            ngx.log(ngx.INFO, "access_0")
            ngx.var.my_var = "changed_in_access"
            ngx.log(ngx.INFO, "access_1")
            ngx.var.my_var = "changed_in_access_2"
            ngx.log(ngx.INFO, "access_2")
            ngx.exit(200)
        }
    }
--- request
GET /test
--- error_log eval
[
    qr/rewrite_0.*request_id: ""$/,
    qr/rewrite_1.*request_id: "changed_in_rewrite"$/,
    qr/rewrite_2.*request_id: "changed_in_rewrite_2"$/,
    qr/access_0.*request_id: "changed_in_rewrite_2"$/,
    qr/access_1.*request_id: "changed_in_access"$/,
    qr/access_2.*request_id: "changed_in_access_2"$/,
]
--- no_error_log
[error]
[crit]
[alert]
