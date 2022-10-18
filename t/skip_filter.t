use t::APISIX_NGINX 'no_plan';

run_tests;

__DATA__

=== TEST 1: skip header_filter_by_lua
--- config
    location /t {
        access_by_lua_block {
            local resp = require("resty.apisix.response")
            assert(resp.skip_header_filter_by_lua())

            ngx.header["Test"] = "one"
            ngx.say("ok")
        }
        header_filter_by_lua_block {
            ngx.header["Test"] = "two"
        }
    }
--- response_headers
Test: one



=== TEST 2: skip body_filter_by_lua
--- config
    location /t {
        access_by_lua_block {
            local resp = require("resty.apisix.response")
            assert(resp.skip_body_filter_by_lua())

            ngx.say("ok")
        }
        body_filter_by_lua_block {
            ngx.arg[1] = "no"
            ngx.arg[2] = true
        }
    }
--- response_body
ok
