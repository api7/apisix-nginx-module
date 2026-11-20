use t::APISIX_NGINX 'no_plan';

# grpc_pass is an HTTP/2 client on every supported runtime, and the backend
# uses "listen ... http2", which, unlike "http2 on", works before nginx 1.25.1.
# So these tests also exercise the HTTP/2 flow control code on OpenResty 1.21.4.
add_block_preprocessor(sub {
    my ($block) = @_;

    my $no_error_log = $block->no_error_log // "[error]\n[alert]";
    $block->set_value("no_error_log",
                      "$no_error_log\nclient violated connection flow control");

    my $http_config = $block->http_config // '';
    $http_config .= <<_EOC_;
    upstream h2_backend {
        server unix:$ENV{TEST_NGINX_HTML_DIR}/h2.sock;
        keepalive 4;
    }

    server {
        listen unix:$ENV{TEST_NGINX_HTML_DIR}/h2.sock http2;
        client_max_body_size 2m;

        location /up {
            content_by_lua_block {
                local size = tonumber(ngx.var.arg_size) or 0
                ngx.header["Content-Length"] = size
                ngx.header["X-Server-Protocol"] = ngx.var.server_protocol
                ngx.print(string.rep("a", size))
            }
        }

        location /echo {
            content_by_lua_block {
                ngx.req.read_body()
                local data = ngx.req.get_body_data()
                if not data then
                    local f = assert(io.open(ngx.req.get_body_file()))
                    data = f:read("*a")
                    f:close()
                end
                ngx.say(ngx.var.server_protocol, " ", #data)
            }
        }
    }
_EOC_

    $block->set_value("http_config", $http_config);
});

run_tests;

__DATA__

=== TEST 1: response larger than the initial flow control window over HTTP/2
--- config
    location /proxy {
        grpc_pass h2_backend;
        rewrite ^ /up break;
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



=== TEST 2: request body larger than the initial flow control window over HTTP/2
--- config
    location /proxy {
        grpc_pass h2_backend;
        rewrite ^ /echo break;
    }

    location /t {
        content_by_lua_block {
            local res = ngx.location.capture("/proxy", {
                method = ngx.HTTP_POST,
                body = string.rep("a", 1024 * 1024),
            })
            ngx.print(res.status, " ", res.body)
        }
    }
--- response_body
200 HTTP/2.0 1048576
