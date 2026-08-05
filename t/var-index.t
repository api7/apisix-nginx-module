use t::APISIX_NGINX 'no_plan';

run_tests;

__DATA__

=== TEST 1: read an indexed variable by index
--- http_config
    apisix_var_index $request_uri $request_method;
    init_worker_by_lua_block {
        require("resty.apisix.var").load_indexes()
    }
--- config
    location /t {
        content_by_lua_block {
            local var = require("resty.apisix.var")
            local idx = var.indexes["request_uri"]
            ngx.say("indexed: ", idx ~= nil)
            ngx.say("by index: ", var.get_by_index(idx))
            ngx.say("by name: ", var.get("request_method"))
            ngx.say("match: ", var.get("request_uri") == ngx.var.request_uri)
        }
    }
--- request
GET /t?a=1
--- response_body
indexed: true
by index: /t?a=1
by name: GET
match: true



=== TEST 2: variable that the configuration did not index falls back to ngx.var
--- http_config
    init_worker_by_lua_block {
        require("resty.apisix.var").load_indexes()
    }
--- config
    location /t {
        content_by_lua_block {
            local var = require("resty.apisix.var")
            ngx.say("indexed: ", var.indexes["http_x_test"] ~= nil)
            ngx.say("value: ", var.get("http_x_test"))
        }
    }
--- more_headers
X-Test: hello
--- response_body
indexed: false
value: hello



=== TEST 3: a variable that is not found returns nil
--- http_config
    apisix_var_index $http_x_absent;
    init_worker_by_lua_block {
        require("resty.apisix.var").load_indexes()
    }
--- config
    location /t {
        content_by_lua_block {
            local var = require("resty.apisix.var")
            ngx.say("indexed: ", var.indexes["http_x_absent"] ~= nil)
            ngx.say("value: ", var.get("http_x_absent") == nil)
        }
    }
--- response_body
indexed: true
value: true



=== TEST 4: write a changeable variable by index
--- http_config
    init_worker_by_lua_block {
        require("resty.apisix.var").load_indexes()
    }
--- config
    set $my_var '';
    location /t {
        content_by_lua_block {
            local var = require("resty.apisix.var")
            ngx.say("indexed: ", var.indexes["my_var"] ~= nil)
            assert(var.set("my_var", "changed"))
            ngx.say("by index: ", var.get("my_var"))
            ngx.say("by ngx.var: ", ngx.var.my_var)
        }
    }
--- response_body
indexed: true
by index: changed
by ngx.var: changed



=== TEST 5: write a variable that has a set_handler
--- http_config
    apisix_var_index $args;
    init_worker_by_lua_block {
        require("resty.apisix.var").load_indexes()
    }
--- config
    location /t {
        content_by_lua_block {
            local var = require("resty.apisix.var")
            assert(var.set("args", "b=2"))
            ngx.say("args: ", ngx.var.args)
            ngx.say("arg_b: ", ngx.var.arg_b)
        }
    }
--- request
GET /t?a=1
--- response_body
args: b=2
arg_b: 2



=== TEST 6: writing a variable that is not changeable reports an error
--- http_config
    apisix_var_index $request_method;
    init_worker_by_lua_block {
        require("resty.apisix.var").load_indexes()
    }
--- config
    location /t {
        content_by_lua_block {
            local var = require("resty.apisix.var")
            local ok, err = var.set("request_method", "POST")
            ngx.say("ok: ", ok)
            ngx.say("err: ", err)
        }
    }
--- response_body
ok: nil
err: variable not changeable



=== TEST 7: setting nil marks the variable as not found
--- http_config
    init_worker_by_lua_block {
        require("resty.apisix.var").load_indexes()
    }
--- config
    set $my_var 'origin';
    location /t {
        content_by_lua_block {
            local var = require("resty.apisix.var")
            ngx.say("before: ", var.get("my_var"))
            assert(var.set("my_var", nil))
            ngx.say("after: ", var.get("my_var") == nil)
        }
    }
--- response_body
before: origin
after: true



=== TEST 8: load_indexes() is rejected in the init phase
--- http_config
    init_by_lua_block {
        local ok, err = pcall(function()
            require("resty.apisix.var").load_indexes()
        end)
        package.loaded.init_err = err
    }
    init_worker_by_lua_block {
        require("resty.apisix.var").load_indexes()
    }
--- config
    location /t {
        content_by_lua_block {
            ngx.say(package.loaded.init_err)
        }
    }
--- response_body_like
.*load_indexes\(\) can not be called in the init phase



=== TEST 9: a prefix variable can be read but not written
--- http_config
    apisix_var_index $http_x_test;
    init_worker_by_lua_block {
        require("resty.apisix.var").load_indexes()
    }
--- config
    location /t {
        content_by_lua_block {
            local var = require("resty.apisix.var")
            ngx.say("read: ", var.get("http_x_test"))
            local ok, err = var.set("http_x_test", "other")
            ngx.say("ok: ", ok)
            ngx.say("err: ", err)
        }
    }
--- more_headers
X-Test: hello
--- response_body
read: hello
ok: nil
err: variable not found for writing



=== TEST 10: apisix_var_index rejects a name without the $ prefix
--- http_config
    apisix_var_index request_uri;
--- config
    location /t {
        content_by_lua_block {
            ngx.say("ok")
        }
    }
--- must_die
--- error_log
invalid variable name "request_uri"



=== TEST 11: apisix_var_index rejects an unknown variable
--- http_config
    apisix_var_index $no_such_variable_here;
--- config
    location /t {
        content_by_lua_block {
            ngx.say("ok")
        }
    }
--- must_die
--- error_log
unknown "no_such_variable_here" variable
