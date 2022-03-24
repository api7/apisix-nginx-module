use t::APISIX_NGINX 'no_plan';

run_tests;

__DATA__

=== TEST 1: get last reopen time without reopen
--- config
    location /t {
        content_by_lua_block {
            local process = require("resty.apisix.process")
            ngx.say(process.get_last_reopen_ms())
        }
    }
--- response_body
0



=== TEST 2: last reopen time
--- config
    location /t {
        content_by_lua_block {
            local now = ngx.now() * 1000
            ngx.sleep(0.01)

            local process = require "ngx.process"
            local resty_signal = require "resty.signal"
            local pid = process.get_master_pid()

            local ok, err = resty_signal.kill(pid, "USR1")
            if not ok then
                ngx.log(ngx.ERR, "failed to kill process of pid ", pid, ": ", err)
                return
            end
            ngx.sleep(0.1)

            local ap = require("resty.apisix.process")
            if ap.get_last_reopen_ms() <= now then
                ngx.say(ap.get_last_reopen_ms(), " ", now)
            else
                ngx.say("ok")
            end
        }
    }
--- response_body
ok
