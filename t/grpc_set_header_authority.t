use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    # gRPC responses carry trailers, so send the request through a raw socket
    my $config = $block->config . <<'_EOC_';
location /t {
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        assert(sock:connect("127.0.0.1", ngx.var.server_port))

        local hdr = ngx.var.http_x_authority
        hdr = hdr and ("X-Authority: " .. hdr .. "\r\n") or ""
        assert(sock:send("POST /a6.RouteService/GetRoute HTTP/1.1\r\nHost: 127.0.0.1:1984\r\n"
                         .. hdr .. "Content-Length: 0\r\nConnection: close\r\n\r\n"))

        local data = assert(sock:receive("*a"))
        assert(string.find(data, "HTTP/1.1 200 OK", 1, true), "status not 200")
        assert(string.find(data, "grpc-status: 0", 1, true), "grpc call failed")
        ngx.say("ok")
    }
}
_EOC_
    $block->set_value("config", $config);
    $block->set_value("response_body", "ok\n");
    $block->set_value("grep_error_log", qr/grpc header: ":authority: [^"]*"/);
});

run_tests();

__DATA__

=== TEST 1: :authority replaces the default one
--- config
location /a6.RouteService/GetRoute {
    access_by_lua_block {
        ngx.req.read_body()
        ngx.req.set_header("Content-Type", "application/grpc")
        ngx.req.set_body_data(ngx.decode_base64("AAAAAAcKBXdvcmxkCgo="))
    }
    grpc_set_header ":authority" "test.com";
    grpc_pass grpc://127.0.0.1:50001;
}
--- grep_error_log_out
grpc header: ":authority: test.com"



=== TEST 2: :authority from a variable
--- config
location /a6.RouteService/GetRoute {
    access_by_lua_block {
        ngx.req.read_body()
        ngx.req.set_header("Content-Type", "application/grpc")
        ngx.req.set_body_data(ngx.decode_base64("AAAAAAcKBXdvcmxkCgo="))
    }
    grpc_set_header ":authority" $http_x_authority;
    grpc_pass grpc://127.0.0.1:50001;
}
--- more_headers
X-Authority: var.test.com
--- grep_error_log_out
grpc header: ":authority: var.test.com"



=== TEST 3: default :authority without grpc_set_header
--- config
location /a6.RouteService/GetRoute {
    access_by_lua_block {
        ngx.req.read_body()
        ngx.req.set_header("Content-Type", "application/grpc")
        ngx.req.set_body_data(ngx.decode_base64("AAAAAAcKBXdvcmxkCgo="))
    }
    grpc_pass grpc://127.0.0.1:50001;
}
--- grep_error_log_out
grpc header: ":authority: 127.0.0.1:50001"
