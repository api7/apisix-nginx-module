use t::APISIX_NGINX 'no_plan';

run_tests();

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->request) {
        $block->set_value("request", "");
    }
});

__DATA__

=== TEST 1: pass upstream trailers to downstream
Since the processing logic for the trailer is located in the upstream and grpc module, it must be tested via grpc_pass.
--- config
location /a6.RouteService/GetRoute {
    access_by_lua_block {
        ngx.req.read_body()
        ngx.req.set_header("Content-Type", "application/grpc")
        ngx.req.set_header("Content-Length", "20")
        ngx.req.set_body_data(ngx.decode_base64("AAAAAAcKBXdvcmxkCgo="))

        -- keep upstream trailers
        assert(require("resty.apisix.upstream").set_pass_trailers(false), 'failed to set pass trailers')
    }
    grpc_pass grpc://127.0.0.1:50001;
}
location /t {
    content_by_lua_block {
        local sock = ngx.socket.tcp()

        local ok, err = sock:connect("127.0.0.1", ngx.var.server_port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end
        local _, err = sock:send("POST /a6.RouteService/GetRoute HTTP/1.1\r\nHost: 127.0.0.1:1984\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        if err then
            ngx.say("failed to send: ", err)
            return
        end

        local data, err, partial = sock:receive("*a")
        if err then
            ngx.say("failed to receive: ", err)
            return
        end

        assert(string.find(data, "HTTP/1.1 200 OK", 1, true), "status not 200")
        assert(not string.find(data, "Trailer: foo", 1, true), "exist trailer header")
        assert(string.find(data, "grpc-status: 0", 1, true), "missing trailer")
    }
}
--- request
GET /t



=== TEST 2: do not pass upstream trailers to downstream
--- config
location /a6.RouteService/GetRoute {
    access_by_lua_block {
        ngx.req.read_body()
        ngx.req.set_header("Content-Type", "application/grpc")
        ngx.req.set_header("Content-Length", "20")
        ngx.req.set_body_data(ngx.decode_base64("AAAAAAcKBXdvcmxkCgo="))

        -- drop upstream trailers
        assert(require("resty.apisix.upstream").set_pass_trailers(false), 'failed to set pass trailers')
    }
    grpc_pass grpc://127.0.0.1:50001;
}
location /t {
    content_by_lua_block {
        local sock = ngx.socket.tcp()

        local ok, err = sock:connect("127.0.0.1", ngx.var.server_port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end
        local _, err = sock:send("POST /a6.RouteService/GetRoute HTTP/1.1\r\nHost: 127.0.0.1:1984\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        if err then
            ngx.say("failed to send: ", err)
            return
        end

        local data, err, partial = sock:receive("*a")
        if err then
            ngx.say("failed to receive: ", err)
            return
        end

        assert(string.find(data, "HTTP/1.1 200 OK", 1, true), "status not 200")
        assert(not string.find(data, "Trailer: foo", 1, true), "exist trailer header")
        assert(not string.find(data, "grpc-status: 0", 1, true), "exist trailer")
    }
}
--- request
GET /t
