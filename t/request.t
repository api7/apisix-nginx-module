use t::APISIX_NGINX 'no_plan';

run_tests;

__DATA__

=== TEST 1: request header flag
--- config
    location /t {
        access_by_lua_block {
            local req = require("resty.apisix.request")
            ngx.say(req.is_request_header_set())
            ngx.req.set_header("A", "b")
            ngx.say(req.is_request_header_set())
            req.clear_request_header()
            ngx.say(req.is_request_header_set())
        }
    }

--- response_body
false
true
false
