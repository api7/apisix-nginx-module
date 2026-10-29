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



=== TEST 2: buffer_size smaller than the default gzip buffer
--- skip_nginx
3: < 1.31.8
--- config
location /t {
    content_by_lua_block {
        -- poorly compressible, so the output needs many buffers
        local t, x = {}, 1
        for i = 1, 16384 do
            x = (x * 1103515245 + 12345) % 2147483648
            t[i] = string.char(33 + x % 94)
        end
        ngx.say(table.concat(t))
    }
    header_filter_by_lua_block {
        local response = require "resty.apisix.response"
        local ok, err = response.set_gzip({
            buffer_num = 64,
            buffer_size = 512,
            compress_level = 1,
        })
        if not ok then
            ngx.log(ngx.ERR, err)
        end
    }
}
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]
[alert]
AddressSanitizer




=== TEST 3: reject buffers zlib can not write into
--- config
location /t {
    content_by_lua_block {
        local response = require "resty.apisix.response"
        for _, b in ipairs({ {0, 8192}, {-1, 8192}, {4, 0} }) do
            local ok, err = response.set_gzip({
                buffer_num = b[1],
                buffer_size = b[2],
                compress_level = 2,
            })
            ngx.say(ok, " ", err)
        end
    }
}
--- response_body
nil bad buffer_num or buffer_size
nil bad buffer_num or buffer_size
nil bad buffer_num or buffer_size
