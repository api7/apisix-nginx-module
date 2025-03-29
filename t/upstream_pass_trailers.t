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
This is the default behavior in the nginx upstream unless we change it.
--- config
location /up {
    # The trailer exists, but the Trailer header does not, which is an invalid response.
    add_trailer "foo" "bar";
    echo "hello";
}
location /t {
    content_by_lua_block {
        local sock = ngx.socket.tcp()

        local ok, err = sock:connect("127.0.0.1", ngx.var.server_port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end
        
        local _, err = sock:send("GET /up HTTP/1.1\r\nHost: 127.0.0.1:1984\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
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
        assert(string.find(data, "foo: bar", 1, true), "missing trailer")
    }
}
--- request
GET /t



=== TEST 2: pass upstream trailers to downstream
Since the processing logic for the trailer is located in the upstream module, it must be tested via proxy_pass.
--- http_config
server {
    listen 1985;
    location /t {
        add_trailer "foo" "bar";
        echo "hello";
    }
}
--- config
location /up {
    proxy_pass http://127.0.0.1:1985/t;
}
location /t {
    access_by_lua_block {
        local upstream = require("resty.apisix.upstream")
        assert(upstream.set_pass_trailers(true), 'failed to set pass trailers')
    }

    content_by_lua_block {
        local sock = ngx.socket.tcp()

        local ok, err = sock:connect("127.0.0.1", ngx.var.server_port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end
        
        local _, err = sock:send("GET /up HTTP/1.1\r\nHost: 127.0.0.1:1984\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
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
        assert(string.find(data, "foo: bar", 1, true), "missing trailer")
    }
}
--- request
GET /t



=== TEST 3: do not pass upstream trailers to downstream
Since the processing logic for the trailer is located in the upstream module, it must be tested via proxy_pass.
--- http_config
server {
    listen 1985;
    location /t {
        add_trailer "foo" "bar";
        echo "hello";
    }
}
--- config
location /up {
    proxy_pass http://127.0.0.1:1985/t;
}
location /t {
    access_by_lua_block {
        local upstream = require("resty.apisix.upstream")
        assert(upstream.set_pass_trailers(false), 'failed to set pass trailers')
    }

    content_by_lua_block {
        local sock = ngx.socket.tcp()

        local ok, err = sock:connect("127.0.0.1", ngx.var.server_port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end
        
        local _, err = sock:send("GET /up HTTP/1.1\r\nHost: 127.0.0.1:1984\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
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
        assert(not string.find(data, "foo: bar", 1, true), "exist trailer")
    }
}
--- request
GET /t
