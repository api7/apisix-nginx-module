use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    my $stream_config = $block->stream_config // '';
    $stream_config .= <<'_EOC_';
    server {
        listen unix:$TEST_NGINX_HTML_DIR/preread.sock;
        ssl_preread on;

        preread_by_lua_block {
            ngx.log(ngx.WARN, "preread server name: [",
                    ngx.var.ssl_preread_server_name, "], protocol: ",
                    ngx.var.ssl_preread_protocol)
        }

        proxy_pass unix:$TEST_NGINX_HTML_DIR/tls.sock;
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/tls.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;

        content_by_lua_block {
            ngx.say("ok")
        }
    }
_EOC_

    $block->set_value("stream_config", $stream_config);
});

run_tests;

__DATA__

=== TEST 1: preread the SNI of a ClientHello
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/preread.sock"))
        local ok, err = sock:sslhandshake(nil, "test.com", false)
        ngx.say("handshake: ", ok and "ok" or err)
        ngx.say(sock:receive())
    }
--- stream_response
handshake: ok
ok
--- error_log eval
qr/preread server name: \[test.com\], protocol: TLSv1\.[23]/



=== TEST 2: preread a ClientHello without SNI
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/preread.sock"))
        local ok, err = sock:sslhandshake(nil, nil, false)
        ngx.say("handshake: ", ok and "ok" or err)
        ngx.say(sock:receive())
    }
--- stream_response
handshake: ok
ok
--- error_log eval
qr/preread server name: \[\], protocol: TLSv1\.[23]/
