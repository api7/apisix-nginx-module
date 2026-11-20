use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    my $http_config = $block->http_config // '';
    $http_config .= <<'_EOC_';
    server {
        listen unix:$TEST_NGINX_HTML_DIR/body.sock ssl;
        server_name test.com;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        client_max_body_size 10m;
        client_body_buffer_size 16k;

        location /up {
            content_by_lua_block {
                ngx.req.read_body()
                local n = 0
                local data = ngx.req.get_body_data()
                if data then
                    n = #data
                else
                    local f = assert(io.open(ngx.req.get_body_file()))
                    n = #f:read("*a")
                    f:close()
                end
                ngx.say(ngx.var.ssl_protocol, " ", n)
            }
        }
    }
_EOC_

    $block->set_value("http_config", $http_config);

    if (!$block->config) {
        my $protocol = $block->ssl_protocol;
        $block->set_value("config", <<_EOC_);
    location /t {
        lua_ssl_protocols $protocol;

        content_by_lua_block {
            local size = 1024 * 1024
            local chunk = string.rep("a", 64 * 1024)

            local function post(chunked)
                local sock = ngx.socket.tcp()
                sock:settimeout(5000)
                assert(sock:connect("unix:\$TEST_NGINX_HTML_DIR/body.sock"))
                assert(sock:sslhandshake(nil, "test.com", false))

                local req = { "POST /up HTTP/1.1\\r\\nHost: test.com\\r\\n",
                              "Connection: close\\r\\n" }
                if chunked then
                    req[#req + 1] = "Transfer-Encoding: chunked\\r\\n\\r\\n"
                    for _ = 1, size / #chunk do
                        req[#req + 1] = string.format("%x\\r\\n", #chunk)
                        req[#req + 1] = chunk
                        req[#req + 1] = "\\r\\n"
                    end
                    req[#req + 1] = "0\\r\\n\\r\\n"
                else
                    req[#req + 1] = "Content-Length: " .. size .. "\\r\\n\\r\\n"
                    req[#req + 1] = string.rep("a", size)
                end

                assert(sock:send(req))
                local res = assert(sock:receive("*a"))
                sock:close()

                return res:match("^HTTP/1.1 (%d+)") .. " "
                       .. res:match("(TLSv1%.%d %d+)")
            end

            ngx.say("fixed: ", post(false))
            ngx.say("chunked: ", post(true))
        }
    }
_EOC_
    }
});

run_tests;

__DATA__

=== TEST 1: read request body over TLSv1.2
--- ssl_protocol: TLSv1.2
--- response_body
fixed: 200 TLSv1.2 1048576
chunked: 200 TLSv1.2 1048576



=== TEST 2: read request body over TLSv1.3
--- ssl_protocol: TLSv1.3
--- response_body
fixed: 200 TLSv1.3 1048576
chunked: 200 TLSv1.3 1048576
