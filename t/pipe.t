use t::APISIX_NGINX 'no_plan';


add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->request) {
        $block->set_value("request", "GET /t");
    }
});

run_tests;

__DATA__

=== TEST 1: check pipe spawn arguments
--- config
    location = /t {
        content_by_lua_block {
            local ngx_pipe = require "ngx.pipe"

            local function check_error(...)
                local data, err = pcall(...)
                if not data then
                    ngx.say(err)
                else
                    ngx.say('ok')
                end
            end

            check_error(ngx_pipe.spawn, nil)
            check_error(ngx_pipe.spawn, {})
            check_error(ngx_pipe.spawn, {"ls"}, {buffer_size = 0})
            check_error(ngx_pipe.spawn, {"ls"}, {buffer_size = 0.5})
            check_error(ngx_pipe.spawn, {"ls"}, {buffer_size = "1"})
            check_error(ngx_pipe.spawn, {"ls"}, {buffer_size = true})
        }
    }
--- request
--- response_body
bad args arg: table expected, got nil
bad args arg: non-empty table expected
bad buffer_size option
bad buffer_size option
ok
bad buffer_size option



=== TEST 2: spawn process, with buffer_size option
--- config
    location = /t {
        content_by_lua_block {
            local ngx_pipe = require "ngx.pipe"
            local proc, err = ngx_pipe.spawn({"ls"}, {buffer_size = 256})
            if not proc then
                ngx.say(err)
            else
                ngx.say('ok')
            end
        }
    }
--- response_body
ok
--- error_log eval
qr/lua pipe spawn process:[0-9A-F]+ pid:\d+ merge_stderr:0 buffer_size:256/
--- no_error_log
[error]



=== TEST 3: ensure process is destroyed in GC
--- config
    location = /t {
        content_by_lua_block {
            local ngx_pipe = require "ngx.pipe"
            do
                local proc, err = ngx_pipe.spawn({"ls", "-l"})
                if not proc then
                    ngx.say(err)
                    return
                end
            end

            collectgarbage()
            ngx.say("ok")
        }
    }
--- response_body
ok
--- no_error_log
[error]
--- error_log
lua pipe destroy process:



=== TEST 4: check phase for process wait
--- config
    location = /t {
        content_by_lua_block {
            local ngx_pipe = require "ngx.pipe"
            local proc, err = ngx_pipe.spawn({"sleep", 0.1})
            if not proc then
                ngx.say(err)
                return
            end

            package.loaded.proc = proc
        }

        log_by_lua_block {
            package.loaded.proc:wait()
        }
    }
--- error_log
API disabled in the context of log_by_lua



=== TEST 5: check process wait arguments
--- config
    location = /t {
        content_by_lua_block {
            local ngx_pipe = require "ngx.pipe"
            local proc, err = ngx_pipe.spawn({"sleep", 0.1})
            proc.wait()
        }
    }
--- error_code: 500
--- ignore_response_body
--- error_log eval
qr/\[error\] .*? runtime error: content_by_lua\(nginx\.conf\:\d+\):\d+: not a process instance/
--- no_error_log
[crit]



=== TEST 6: wait an already waited process
--- config
    location = /t {
        content_by_lua_block {
            local ngx_pipe = require "ngx.pipe"
            local proc, err = ngx_pipe.spawn({"ls"})
            if not proc then
                ngx.say(err)
                return
            end

            local ok, err = proc:wait()
            if not ok then
                ngx.say(err)
                return
            end

            local ok, err = proc:wait()
            if not ok then
                ngx.say(err)
            end
        }
    }
--- response_body
exited



=== TEST 7: more than one coroutines wait a process
--- config
    location = /t {
        content_by_lua_block {
            local ngx_pipe = require "ngx.pipe"
            local proc, err = ngx_pipe.spawn({"sleep", 0.1})
            if not proc then
                ngx.say(err)
                return
            end

            local function wait()
                local ok, err = proc:wait()
                if not ok then
                    ngx.say(err)
                end
            end

            local th1 = ngx.thread.spawn(wait)
            local th2 = ngx.thread.spawn(wait)
            ngx.thread.wait(th1)
            ngx.thread.wait(th2)
            ngx.thread.spawn(wait)
        }
    }
--- response_body
pipe busy waiting
exited



=== TEST 8: kill living sub-process during Lua VM destruction.
--- config
    location = /t {
        content_by_lua_block {
            local ngx_pipe = require "ngx.pipe"
            local proc, err = ngx_pipe.spawn({"sleep", 3600})
            if not proc then
                ngx.say(err)
                return
            end
            ngx.say("ok")
        }
    }
--- response_body
ok
--- shutdown_error_log
lua pipe destroy process:
lua pipe kill process:
