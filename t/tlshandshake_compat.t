our $SkipReason;

BEGIN {
    my $nginx_binary = $ENV{'TEST_NGINX_BINARY'} || 'nginx';
    my $version = eval { `$nginx_binary -V 2>&1` } // '';
    my ($major, $minor) = $version =~ m{openresty/(\d+)\.(\d+)};

    if (!defined $major || !defined $minor
        || ($major < 1 || ($major == 1 && $minor < 29))) {
        $SkipReason = "requires OpenResty 1.29 or later";
    }
}

use t::APISIX_NGINX $SkipReason
    ? (skip_all => $SkipReason)
    : ('no_plan');

no_root_location();
run_tests();

__DATA__

=== TEST 1: sslhandshake works on both ngx.socket.tcp() and ngx.socket.stream() objects (http)
--- config
    listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
    ssl_certificate ../../certs/test.crt;
    ssl_certificate_key ../../certs/test.key;

    location = /up {
        return 200 'ok';
    }

    location = /t {
        content_by_lua_block {
            for _, ctor in ipairs({"tcp", "stream"}) do
                local sock = ngx.socket[ctor]()
                sock:settimeout(2000)
                assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock"))

                local pok, sess, err = pcall(sock.sslhandshake, sock,
                                             nil, nil, false)
                ngx.say(ctor, " pcall: ", pok, ", session: ",
                        sess ~= nil, ", err: ", err)
                sock:close()
            end
        }
    }
--- response_body
tcp pcall: true, session: true, err: nil
stream pcall: true, session: true, err: nil



=== TEST 2: tlshandshake works on both ngx.socket.tcp() and ngx.socket.stream() objects (http)
--- config
    listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
    ssl_certificate ../../certs/test.crt;
    ssl_certificate_key ../../certs/test.key;

    location = /up {
        return 200 'ok';
    }

    location = /t {
        content_by_lua_block {
            for _, ctor in ipairs({"tcp", "stream"}) do
                local sock = ngx.socket[ctor]()
                sock:settimeout(2000)
                assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock"))

                local pok, sess, err = pcall(sock.tlshandshake, sock)
                ngx.say(ctor, " pcall: ", pok, ", session: ",
                        sess ~= nil, ", err: ", err)
                sock:close()
            end
        }
    }
--- response_body
tcp pcall: true, session: true, err: nil
stream pcall: true, session: true, err: nil



=== TEST 3: sslhandshake/tlshandshake work on both constructors (stream subsystem)
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/stream_tls.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        content_by_lua_block {
            local sk = assert(ngx.req.socket(true))
            sk:send("hello")
        }
    }
--- stream_server_config
    content_by_lua_block {
        for _, ctor in ipairs({"tcp", "stream"}) do
            local sock = ngx.socket[ctor]()
            sock:settimeout(2000)
            assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/stream_tls.sock"))

            local pok, sess, err = pcall(sock.sslhandshake, sock,
                                         nil, nil, false)
            ngx.say(ctor, " ssl pcall: ", pok, ", session: ",
                    sess ~= nil, ", err: ", err)
            sock:close()

            sock = ngx.socket[ctor]()
            sock:settimeout(2000)
            assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/stream_tls.sock"))

            pok, sess, err = pcall(sock.tlshandshake, sock)
            ngx.say(ctor, " tls pcall: ", pok, ", session: ",
                    sess ~= nil, ", err: ", err)
            sock:close()
        end
    }
--- stream_request
--- stream_response
tcp ssl pcall: true, session: true, err: nil
tcp tls pcall: true, session: true, err: nil
stream ssl pcall: true, session: true, err: nil
stream tls pcall: true, session: true, err: nil



=== TEST 4: file-based TLS options can be reused across connections
--- config
    listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
    ssl_certificate ../../certs/mtls_server.crt;
    ssl_certificate_key ../../certs/mtls_server.key;
    ssl_client_certificate ../../certs/mtls_ca.crt;
    ssl_verify_client on;

    location = /up {
        return 200 "ok\n";
    }

    location = /t {
        content_by_lua_block {
            local options = {
                client_cert_path = "t/certs/mtls_client.crt",
                client_priv_key_path = "t/certs/mtls_client.key",
            }

            for i = 1, 2 do
                local sock = ngx.socket.tcp()
                sock:settimeout(2000)
                assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock"))

                local pok, sess, err = pcall(sock.tlshandshake, sock, options)
                ngx.say(i, " pcall: ", pok, ", session: ",
                        sess ~= nil, ", err: ", err)

                if pok and sess then
                    assert(sock:send("GET /up HTTP/1.0\r\nHost: localhost\r\n\r\n"))
                    assert(sock:receive("*a"))
                end
                sock:close()
            end

            ngx.say("options untouched: ",
                    options.client_cert == nil and
                    options.client_priv_key == nil)
        }
    }
--- response_body
1 pcall: true, session: true, err: nil
2 pcall: true, session: true, err: nil
options untouched: true
