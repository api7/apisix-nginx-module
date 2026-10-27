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
            local ms = ap.get_last_reopen_ms()
            if ms == 0 or ms <= now then
                ngx.say(ms, " ", now)
            else
                ngx.say("ok")
            end
        }
    }
--- response_body
ok



=== TEST 3: generation and identity of a single process
--- config
    location /t {
        content_by_lua_block {
            local process = require("resty.apisix.process")
            ngx.say("generation: ", process.get_generation())

            local id = assert(process.get_identity())
            ngx.say(id.type, " worker_id=", id.worker_id, " slot=", id.slot,
                    " count=", id.worker_count, " pid=",
                    id.pid == ngx.worker.pid(), " generation=", id.generation)
        }
    }
--- response_body
generation: 1
single worker_id=0 slot=0 count=1 pid=true generation=1



=== TEST 4: no generation before the first configuration is committed
--- http_config
    init_by_lua_block {
        local process = require("resty.apisix.process")
        ngx.log(ngx.WARN, "generation in init: ", process.get_generation())
    }
--- config
    location /t {
        return 200;
    }
--- error_log
generation in init: 0
