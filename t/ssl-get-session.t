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
run_tests;

__DATA__

=== TEST 1: getsslsession remains usable after tlshandshake
--- config
    listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
    ssl_certificate ../../certs/test.crt;
    ssl_certificate_key ../../certs/test.key;
    ssl_protocols TLSv1.2;

    location = /up {
        return 200 'ok';
    }

    location = /t {
        lua_ssl_protocols TLSv1.2;
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock"))
            assert(sock:tlshandshake())
            assert(sock:send("GET /up HTTP/1.1\r\n" ..
                             "Host: localhost\r\n" ..
                             "Connection: keep-alive\r\n\r\n"))

            assert(sock:receive("*l"))
            while true do
                local line = assert(sock:receive("*l"))
                if line == "" then
                    break
                end
            end
            assert(sock:receive(2))

            local ok, session = pcall(sock.getsslsession, sock)
            ngx.say("pcall: ", ok)
            ngx.say("session: ", type(session))
        }
    }
--- response_body
pcall: true
session: cdata
