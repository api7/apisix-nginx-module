use t::APISIX_NGINX 'no_plan';

run_tests();

__DATA__

=== TEST 1: mirror
--- config
location /mirror {
    content_by_lua_block {
        ngx.log(ngx.WARN, "mirror request with ", ngx.req.get_method())
    }
}
location /t {
    mirror /mirror;
    content_by_lua_block {
        ngx.exit(200)
    }
}
--- request
POST /t
blahblah
--- grep_error_log eval
qr/mirror request with \w+/
--- grep_error_log_out
mirror request with POST



=== TEST 2: mirror on demand
--- config
location /mirror {
    content_by_lua_block {
        ngx.log(ngx.WARN, "mirror request with ", ngx.req.get_method())
    }
}
location /t {
    mirror /mirror;
    apisix_mirror_on_demand on;
    content_by_lua_block {
        ngx.exit(200)
    }
}
--- request
POST /t
blahblah
--- grep_error_log eval
qr/mirror request with \w+/
--- grep_error_log_out



=== TEST 3: mirror on demand, enabled
--- config
location /mirror {
    content_by_lua_block {
        ngx.log(ngx.WARN, "mirror request with ", ngx.req.get_method())
    }
}
location /t {
    mirror /mirror;
    apisix_mirror_on_demand on;
    access_by_lua_block {
        local client = require("resty.apisix.client")
        assert(client.enable_mirror())
    }
    content_by_lua_block {
        ngx.exit(200)
    }
}
--- request
POST /t
blahblah
--- grep_error_log eval
qr/mirror request with \w+/
--- grep_error_log_out
mirror request with POST
