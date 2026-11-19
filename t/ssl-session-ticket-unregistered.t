our $SkipReason;

BEGIN {
    # every registration of the ticket key callback fails, as if OpenSSL
    # refused it: a debug build only
    $ENV{APISIX_TEST_SSL_SESSION_TICKET_REGISTER_FAIL} = 1;

    my $nginx_binary = $ENV{'TEST_NGINX_BINARY'} || 'nginx';
    my $version = eval { `$nginx_binary -V 2>&1` } // '';
    if ($version !~ m{openresty/1\.31\.1\.}) {
        # the takeover patch only exists for this bundle
        $SkipReason = "the session ticket takeover needs OpenResty 1.31.1";

    } elsif ($version !~ /--with-debug/) {
        $SkipReason = "requires a build --with-debug";
    }
}

use t::APISIX_NGINX $SkipReason
    ? (skip_all => $SkipReason)
    : ('no_plan');

repeat_each(1);

run_tests;

__DATA__

=== TEST 1: http, a failed registration keeps the context off and says so
The server asks for tickets explicitly; without a registered callback that
would mean the keys OpenSSL makes up, so the context stays off instead.
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/a.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        ssl_session_tickets on;
        apisix_ssl_session_ticket_takeover on;

        location / {
            content_by_lua_block {
                require("t.lib.ssl_session_ticket").respond()
            }
        }
    }
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")

            local ctx = assert(ticket.contexts())[1]
            ngx.say("registered=", ctx.registered, " tickets=", ctx.tickets)

            ngx.say(ticket.set_keys(1, h.keys(1)))
            ngx.say(ticket.enable_tickets(1))
            ngx.say(ticket.disable_tickets(1))
            ngx.say(ticket.revoke_keys(1))

            local r = assert(h.connect("unix:$TEST_NGINX_HTML_DIR/a.sock",
                                       {http = true}))
            ngx.say("ticket: ", r.ticket, ", connection tickets: ",
                    r.conn_tickets)
        }
    }
--- response_body
registered=false tickets=false
nilnot_registered
nilnot_registered
true
true
ticket: nil, connection tickets: 0
--- error_log eval
qr/\[error\] .*failed to register the session ticket key callback, session tickets stay off for the server in \S+nginx\.conf:\d+/
--- no_error_log
apisix ssl ticket
[alert]



=== TEST 2: stream, a failed registration keeps the context off and says so
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/a.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        apisix_ssl_session_ticket_takeover on;

        content_by_lua_block {
            require("t.lib.ssl_session_ticket").respond()
        }
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/ctl.sock;

        content_by_lua_block {
            require("t.lib.ssl_session_ticket").control()
        }
    }
--- stream_server_config
    return unused;
--- config
    location = /test {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"

            ngx.say(h.stream(ctl, "contexts"))
            ngx.say(h.stream(ctl, "set_keys 1 1"))
            ngx.say(h.stream(ctl, "enable_tickets 1"))

            local r = assert(h.connect("unix:$TEST_NGINX_HTML_DIR/a.sock"))
            ngx.say("ticket: ", r.ticket, ", connection tickets: ",
                    r.conn_tickets)
        }
    }
--- request
GET /test
--- response_body
1 registered=false tickets=false keys=0
not_registered
not_registered
ticket: nil, connection tickets: 0
--- error_log eval
qr/\[error\] .*failed to register the session ticket key callback, session tickets stay off for the server in \S+nginx\.conf:\d+/
--- no_error_log
apisix ssl ticket
[alert]
