use t::APISIX_NGINX 'no_plan';

run_tests;

__DATA__

=== TEST 1: set real ip
--- config
    location /t {
        content_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_real_ip("127.0.0.2"))
            ngx.say(ngx.var.remote_addr)
            ngx.say(ngx.var.remote_port == ngx.var.realip_remote_port)
            ngx.say(ngx.var.realip_remote_addr)
        }
    }
--- response_body
127.0.0.2
true
127.0.0.1



=== TEST 2: set real ip & port
--- config
    location /t {
        content_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_real_ip("172.1.1.2", 1289))
            ngx.say(ngx.var.remote_addr)
            ngx.say(ngx.var.remote_port == "1289")
            ngx.say(ngx.var.realip_remote_addr)
        }
    }
--- response_body
172.1.1.2
true
127.0.0.1



=== TEST 3: IPv6
--- config
    location /t {
        content_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_real_ip("1::2"))
            ngx.say(ngx.var.remote_addr)
            ngx.say(ngx.var.remote_port == ngx.var.realip_remote_port)
        }
    }
--- response_body
1::2
true



=== TEST 4: call twice
--- http_config
    log_format log '$realip_remote_addr:$realip_remote_port $remote_addr:$remote_port';
--- config
    access_log logs/access.log log;
    location /t {
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_real_ip("172.1.2.3", 1234))
        }
        content_by_lua_block {
            local client = require("resty.apisix.client")
            ngx.say(ngx.var.remote_addr)
            ngx.say(ngx.var.realip_remote_addr)
            ngx.say(ngx.var.remote_port)
            assert(client.set_real_ip("172.1.1.2", 12890))
            ngx.say(ngx.var.remote_addr)
            ngx.say(ngx.var.remote_port)
            ngx.say(ngx.var.realip_remote_addr)
            ngx.say(ngx.var.realip_remote_port)
        }
    }
--- response_body
172.1.2.3
127.0.0.1
1234
172.1.1.2
12890
172.1.2.3
1234
--- access_log
172.1.2.3:1234 172.1.1.2:12890



=== TEST 5: use with realip module
--- http_config
    log_format log '$realip_remote_addr:$realip_remote_port $remote_addr:$remote_port';
--- config
    access_log logs/access.log log;
    set_real_ip_from 0.0.0.0/0;
    real_ip_header X-Forwarded-For;
    location /t {
        content_by_lua_block {
            local client = require("resty.apisix.client")
            ngx.say(ngx.var.remote_addr)
            ngx.say(ngx.var.realip_remote_addr)
            ngx.say(ngx.var.remote_port)
            assert(client.set_real_ip("172.1.1.2", 12890))
            ngx.say(ngx.var.remote_addr)
            ngx.say(ngx.var.remote_port)
            ngx.say(ngx.var.realip_remote_addr)
            ngx.say(ngx.var.realip_remote_port)
        }
    }
--- more_headers
X-Forwarded-For: 172.1.2.3:1234
--- response_body
172.1.2.3
127.0.0.1
1234
172.1.1.2
12890
172.1.2.3
1234
--- access_log
172.1.2.3:1234 172.1.1.2:12890



=== TEST 6: use with realip module, no port
--- http_config
    log_format log '$realip_remote_addr:$realip_remote_port $remote_addr:$remote_port';
--- config
    access_log logs/access.log log;
    set_real_ip_from 0.0.0.0/0;
    real_ip_header X-Forwarded-For;
    location /t {
        content_by_lua_block {
            local client = require("resty.apisix.client")
            ngx.say(ngx.var.remote_addr)
            ngx.say(ngx.var.realip_remote_addr)
            ngx.say(ngx.var.remote_port)
            assert(client.set_real_ip("172.1.1.2", 12890))
            ngx.say(ngx.var.remote_addr)
            ngx.say(ngx.var.remote_port)
            ngx.say(ngx.var.realip_remote_port)
            ngx.say(ngx.var.realip_remote_addr)
        }
    }
--- more_headers
X-Forwarded-For: 172.1.2.3
--- response_body
172.1.2.3
127.0.0.1

172.1.1.2
12890

172.1.2.3
--- access_log
172.1.2.3: 172.1.1.2:12890
