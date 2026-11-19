use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    my $http_config = $block->http_config // '';
    $http_config .= <<_EOC_;
    upstream h2_backend {
        server unix:$ENV{TEST_NGINX_HTML_DIR}/h2.sock;
        keepalive 4;
    }

    server {
        listen unix:$ENV{TEST_NGINX_HTML_DIR}/h2.sock;
        http2 on;

        location /up {
            content_by_lua_block {
                local size = tonumber(ngx.var.arg_size) or 0
                ngx.header["Content-Length"] = size
                ngx.header["X-Server-Protocol"] = ngx.var.server_protocol
                ngx.print(string.rep("a", size))
            }
        }
    }
_EOC_

    $block->set_value("http_config", $http_config);

    my $no_error_log = $block->no_error_log // "[error]\n[alert]";
    $block->set_value("no_error_log",
                      "$no_error_log\nclient violated connection flow control");
});

run_tests;

__DATA__

=== TEST 1: response larger than the initial flow control window over HTTP/2
--- skip_nginx
3: < 1.31.1
--- config
    location /proxy {
        proxy_http_version 2;
        proxy_pass http://h2_backend/up;
    }

    location /t {
        content_by_lua_block {
            local res = ngx.location.capture("/proxy", {
                args = { size = 1024 * 1024 },
            })
            ngx.say(res.header["x-server-protocol"], " ", res.status, " ",
                    #res.body)
        }
    }
--- response_body
HTTP/2.0 200 1048576



=== TEST 2: sequential streams on a kept-alive HTTP/2 connection
--- skip_nginx
3: < 1.31.1
--- config
    location /proxy {
        proxy_http_version 2;
        proxy_pass http://h2_backend/up;
    }

    location /t {
        content_by_lua_block {
            for i = 1, 5 do
                local res = ngx.location.capture("/proxy", {
                    args = { size = 128 * 1024 },
                })
                ngx.say(i, ": ", res.status, " ", #res.body)
            end
        }
    }
--- response_body
1: 200 131072
2: 200 131072
3: 200 131072
4: 200 131072
5: 200 131072



=== TEST 3: concurrent streams on HTTP/2 connections
--- skip_nginx
3: < 1.31.1
--- config
    location /proxy {
        proxy_http_version 2;
        proxy_pass http://h2_backend/up;
    }

    location /t {
        content_by_lua_block {
            local reqs = {}
            for i = 1, 8 do
                reqs[i] = { "/proxy", { args = { size = 256 * 1024 } } }
            end

            local resps = { ngx.location.capture_multi(reqs) }
            for i, res in ipairs(resps) do
                ngx.say(i, ": ", res.status, " ", #res.body)
            end
        }
    }
--- response_body
1: 200 262144
2: 200 262144
3: 200 262144
4: 200 262144
5: 200 262144
6: 200 262144
7: 200 262144
8: 200 262144
