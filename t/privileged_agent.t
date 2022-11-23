use t::APISIX_NGINX 'no_plan';

master_on();
run_tests();

__DATA__

=== TEST 1: sanity
--- http_config
init_by_lua_block {
    local process = require("ngx.process")
    assert(process.enable_privileged_agent())
}
server {
    listen 9090;
    location / {
        content_by_lua_block {
            local process = require("ngx.process")
            ngx.say(process.type())
        }
    }
}
server {
    listen 127.0.0.1:9091 enable_process=privileged_agent;
    location / {
        content_by_lua_block {
            local process = require("ngx.process")
            ngx.say(process.type())
        }
    }
}
--- config
    location /t {
        content_by_lua_block {
            local http = require "resty.http"

            for i = 1, 12 do
                local httpc = http.new()
                local uri
                if i % 2 == 1 then
                    uri = "http://127.0.0.1:9090"
                else
                    uri = "http://127.0.0.1:9091"
                end
                local res, err = httpc:request_uri(uri, {method = "GET"})
                if not res then
                    ngx.say(err)
                    return
                end

                local exp
                if i % 2 == 1 then
                    exp = "worker\n"
                else
                    exp = "privileged agent\n"
                end

                assert(exp == res.body)
            end
        }
    }



=== TEST 2: address conflict detection
--- http_config
init_by_lua_block {
    local process = require("ngx.process")
    assert(process.enable_privileged_agent())
}
server {
    listen 127.0.0.1:9091;
    location / {
        content_by_lua_block {
            local process = require("ngx.process")
            ngx.say(process.type())
        }
    }
}
server {
    listen 127.0.0.1:9091 enable_process=privileged_agent;
    location / {
        content_by_lua_block {
            local process = require("ngx.process")
            ngx.say(process.type())
        }
    }
}
--- config
    location /t {
        return 200;
    }
--- must_die
--- error_log
127.0.0.1:9091 is already occupied by privileged agent



=== TEST 3: same port, different IP
--- http_config
init_by_lua_block {
    local process = require("ngx.process")
    assert(process.enable_privileged_agent())
}
server {
    listen 9091;
    location / {
        content_by_lua_block {
            local process = require("ngx.process")
            ngx.say(process.type())
        }
    }
}
server {
    listen 127.0.0.1:9091 enable_process=privileged_agent;
    location / {
        content_by_lua_block {
            local process = require("ngx.process")
            ngx.say(process.type())
        }
    }
}
--- config
    location /t {
        return 200;
    }
