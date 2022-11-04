use t::APISIX_NGINX 'no_plan';

run_tests();

__DATA__

=== TEST 1: ngx.say (integer)
--- config
    location /t {
        content_by_lua_block {
            local str = string.rep(".", 1300)
            ngx.print(str)
            ngx.flush()
            ngx.print("small chunk")
            ngx.flush()
        }
        body_filter_by_lua_block {local dummy=1}
    }
--- request
GET /t
--- response_body_like: small chunk
