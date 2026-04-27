use t::APISIX_NGINX 'no_plan';

repeat_each(2);

run_tests();

__DATA__

=== TEST 1: push upstream state - status and addr
--- config
    log_format upstream_test '$upstream_status $upstream_addr';
    access_log logs/upstream_test.log upstream_test;
    location /t {
        content_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ok, err = upstream.push_upstream_state({
                addr = "1.2.3.4:8080",
                status = 200,
            })
            if not ok then
                ngx.say("push failed: ", err)
                return
            end
            ngx.say("ok")
        }
    }
--- response_body
ok
--- access_log eval
qr/200 1\.2\.3\.4:8080/
--- log_file: upstream_test.log


=== TEST 2: push upstream state - all timing fields
--- config
    log_format upstream_timing '$upstream_status $upstream_connect_time $upstream_header_time $upstream_response_time $upstream_response_length';
    access_log logs/upstream_timing.log upstream_timing;
    location /t {
        content_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ok, err = upstream.push_upstream_state({
                addr = "10.0.0.1:443",
                status = 200,
                connect_time = 50,
                header_time = 120,
            })
            if not ok then
                ngx.say("push failed: ", err)
                return
            end

            local ok, err = upstream.update_upstream_state({
                response_time = 1500,
                response_length = 4096,
            })
            if not ok then
                ngx.say("update failed: ", err)
                return
            end
            ngx.say("ok")
        }
    }
--- response_body
ok
--- access_log eval
qr/200 0\.050 0\.120 1\.500 4096/
--- log_file: upstream_timing.log


=== TEST 3: push upstream state - unset timings render as dash
--- config
    log_format upstream_dash '$upstream_status $upstream_connect_time $upstream_header_time $upstream_response_time $upstream_response_length';
    access_log logs/upstream_dash.log upstream_dash;
    location /t {
        content_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ok, err = upstream.push_upstream_state({
                addr = "10.0.0.1:443",
                status = 502,
            })
            if not ok then
                ngx.say("push failed: ", err)
                return
            end
            ngx.say("ok")
        }
    }
--- response_body
ok
--- access_log eval
qr/502 - - - -/
--- log_file: upstream_dash.log


=== TEST 4: update upstream state without push fails
--- config
    location /t {
        content_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ok, err = upstream.update_upstream_state({
                response_time = 100,
            })
            if not ok then
                ngx.say("expected error: ", err)
                return
            end
            ngx.say("should not reach here")
        }
    }
--- response_body
expected error: error while updating upstream state


=== TEST 5: multiple push calls (retry scenario)
--- config
    log_format upstream_retry '$upstream_status $upstream_addr';
    access_log logs/upstream_retry.log upstream_retry;
    location /t {
        content_by_lua_block {
            local upstream = require("resty.apisix.upstream")

            -- first attempt fails
            upstream.push_upstream_state({
                addr = "10.0.0.1:443",
                status = 502,
                connect_time = 30,
            })
            upstream.update_upstream_state({
                response_time = 50,
            })

            -- second attempt succeeds
            upstream.push_upstream_state({
                addr = "10.0.0.2:443",
                status = 200,
                connect_time = 20,
                header_time = 80,
            })
            upstream.update_upstream_state({
                response_time = 500,
                response_length = 2048,
            })

            ngx.say("ok")
        }
    }
--- response_body
ok
--- access_log eval
qr/502, 200 10\.0\.0\.1:443, 10\.0\.0\.2:443/
--- log_file: upstream_retry.log


=== TEST 6: push upstream state with no addr
--- config
    log_format upstream_noaddr '$upstream_status';
    access_log logs/upstream_noaddr.log upstream_noaddr;
    location /t {
        content_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            local ok, err = upstream.push_upstream_state({
                status = 200,
            })
            if not ok then
                ngx.say("push failed: ", err)
                return
            end
            ngx.say("ok")
        }
    }
--- response_body
ok
--- access_log eval
qr/200/
--- log_file: upstream_noaddr.log


=== TEST 7: lua-var-nginx-module can read the pushed upstream state timings
--- config
    location /t {
        content_by_lua_block {
            local upstream = require("resty.apisix.upstream")
            upstream.push_upstream_state({
                addr = "10.0.0.1:443",
                status = 200,
                connect_time = 50,
                header_time = 120,
            })
            upstream.update_upstream_state({
                response_time = 1500,
            })

            local var = require("resty.ngxvar")
            local req = var.request()
            ngx.say("response_time: ", var.fetch("upstream_response_time", req))
            ngx.say("header_time: ", var.fetch("upstream_header_time", req))
            ngx.say("connect_time: ", var.fetch("upstream_connect_time", req))
        }
    }
--- response_body
response_time: 1.5
header_time: 0.12
connect_time: 0.05
