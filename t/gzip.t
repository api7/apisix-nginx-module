use t::APISIX_NGINX 'no_plan';

run_tests();

__DATA__

=== TEST 1: set gzip
--- config
location /t {
    content_by_lua_block {
        ngx.say(("1024"):rep(1024))
    }
    header_filter_by_lua_block {
        local response = require "resty.apisix.response"
        local ok, err = response.set_gzip({
            buffer_num = 4,
            buffer_size = 8192,
            compress_level = 2,
        })
        if not ok then
            ngx.log(ngx.ERR, err)
        end
    }
    log_by_lua_block {
        ngx.log(ngx.WARN, "content-encoding: ", ngx.var.sent_http_content_encoding)
    }
}
--- more_headers
Accept-Encoding: gzip
--- error_log
apisix gzip level:2
apisix gzip num:4 size:8192
content-encoding: gzip
--- no_error_log
[error]
