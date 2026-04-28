use t::APISIX_NGINX 'no_plan';

repeat_each(2);

run_tests();

__DATA__

=== TEST 1: push upstream state - status and addr via ngx.var
--- config
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
            ngx.say("status: ", ngx.var.upstream_status)
            ngx.say("addr: ", ngx.var.upstream_addr)
        }
    }
--- response_body
status: 200
addr: 1.2.3.4:8080



=== TEST 2: push + update upstream state - all timing fields
--- config
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

            ngx.say("status: ", ngx.var.upstream_status)
            ngx.say("connect_time: ", ngx.var.upstream_connect_time)
            ngx.say("header_time: ", ngx.var.upstream_header_time)
            ngx.say("response_time: ", ngx.var.upstream_response_time)
            ngx.say("response_length: ", ngx.var.upstream_response_length)
        }
    }
--- response_body
status: 200
connect_time: 0.050
header_time: 0.120
response_time: 1.500
response_length: 4096



=== TEST 3: push upstream state - unset timings render as dash
--- config
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
            ngx.say("status: ", ngx.var.upstream_status)
            ngx.say("connect_time: ", ngx.var.upstream_connect_time)
            ngx.say("header_time: ", ngx.var.upstream_header_time)
            ngx.say("response_time: ", ngx.var.upstream_response_time)
            ngx.say("response_length: ", ngx.var.upstream_response_length)
        }
    }
--- response_body
status: 502
connect_time: -
header_time: -
response_time: -
response_length: 0



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

            ngx.say("status: ", ngx.var.upstream_status)
            ngx.say("addr: ", ngx.var.upstream_addr)
        }
    }
--- response_body
status: 502, 200
addr: 10.0.0.1:443, 10.0.0.2:443



=== TEST 6: push upstream state with no addr
--- config
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
            ngx.say("status: ", ngx.var.upstream_status)
        }
    }
--- response_body
status: 200



=== TEST 7: push and update upstream state verified via ngx.var (integration check)
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
                response_length = 8192,
            })

            ngx.say("status: ", ngx.var.upstream_status)
            ngx.say("addr: ", ngx.var.upstream_addr)
            ngx.say("response_time: ", ngx.var.upstream_response_time)
            ngx.say("header_time: ", ngx.var.upstream_header_time)
            ngx.say("connect_time: ", ngx.var.upstream_connect_time)
            ngx.say("response_length: ", ngx.var.upstream_response_length)
        }
    }
--- response_body
status: 200
addr: 10.0.0.1:443
response_time: 1.500
header_time: 0.120
connect_time: 0.050
response_length: 8192



=== TEST 8: access log with upstream state from cosocket request
--- http_config
    log_format upstream_log '$upstream_status $upstream_addr $upstream_response_time $upstream_header_time $upstream_connect_time $upstream_response_length';
    server {
        listen 10888;
        location / {
            content_by_lua_block {
                ngx.say("hello from upstream")
            }
        }
    }
--- config
    access_log logs/access.log upstream_log;
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local httpc = http.new()

            local t0 = ngx.now()
            local ok, err = httpc:connect("127.0.0.1", 10888)
            if not ok then
                ngx.say("connect failed: ", err)
                return
            end
            local connect_time = math.floor((ngx.now() - t0) * 1000)

            local res, err = httpc:request({
                method = "GET",
                path = "/",
            })
            if not res then
                ngx.say("request failed: ", err)
                return
            end
            local header_time = math.floor((ngx.now() - t0) * 1000)

            local body = res:read_body()
            local response_time = math.floor((ngx.now() - t0) * 1000)

            local upstream = require("resty.apisix.upstream")
            upstream.push_upstream_state({
                addr = "127.0.0.1:10888",
                status = res.status,
                connect_time = connect_time,
                header_time = header_time,
            })
            upstream.update_upstream_state({
                response_time = response_time,
                response_length = #body,
            })

            httpc:set_keepalive()
            ngx.say("done")
        }
    }
--- response_body
done
--- access_log eval
qr/200 127\.0\.0\.1:10888 \d+\.\d{3} \d+\.\d{3} \d+\.\d{3} 20\n/
