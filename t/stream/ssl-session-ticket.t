our ($SkipReason, $NoDebug);

BEGIN {
    # test key 51 fails to encrypt a ticket, see t/ssl-session-ticket.t
    $ENV{APISIX_TEST_SSL_SESSION_TICKET_FAIL_ENCRYPT} = "33" x 16;

    my $nginx_binary = $ENV{'TEST_NGINX_BINARY'} || 'nginx';
    my $version = eval { `$nginx_binary -V 2>&1` } // '';
    $NoDebug = $version !~ /--with-debug/;

    # the takeover patch only exists for this bundle
    if ($version !~ m{openresty/1\.31\.1\.}) {
        $SkipReason = "the session ticket takeover needs OpenResty 1.31.1";
    }
}

use t::APISIX_NGINX $SkipReason
    ? (skip_all => $SkipReason)
    : ('no_plan');

repeat_each(1);

add_block_preprocessor(sub {
    my ($block) = @_;

    # Nodes A and B stand for two gateways of a cluster, with the stream
    # defaults: no session cache at all. The client side and the control of
    # the stream contexts run in the http subsystem, see t/lib.
    if (!$block->stream_config) {
        my $stream_config = <<'_EOC_';
    server {
        listen unix:$TEST_NGINX_HTML_DIR/a.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        ssl_session_tickets off;
        apisix_ssl_session_ticket_takeover on;

        ssl_client_hello_by_lua_block {
            require("t.lib.ssl_session_ticket").client_hello()
        }

        ssl_certificate_by_lua_block {
            require("t.lib.ssl_session_ticket").certificate()
        }

        content_by_lua_block {
            require("t.lib.ssl_session_ticket").respond()
        }
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/b.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        # tickets at the native default: the mark starts them off anyway
        apisix_ssl_session_ticket_takeover on;

        ssl_client_hello_by_lua_block {
            require("t.lib.ssl_session_ticket").client_hello()
        }

        content_by_lua_block {
            require("t.lib.ssl_session_ticket").respond()
        }
    }

    # a long-lived session, answering each line
    server {
        listen unix:$TEST_NGINX_HTML_DIR/lines.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        apisix_ssl_session_ticket_takeover on;

        ssl_client_hello_by_lua_block {
            require("t.lib.ssl_session_ticket").client_hello()
        }

        content_by_lua_block {
            require("t.lib.ssl_session_ticket").serve_lines()
        }
    }

    # not marked: the native stream default, tickets on with the keys
    # OpenSSL makes up for the context
    server {
        listen unix:$TEST_NGINX_HTML_DIR/native.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;

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
_EOC_

        $block->set_value("stream_config", $stream_config);
    }

    if (!$block->stream_server_config) {
        $block->set_value("stream_server_config", "return unused;");
    }

    if (!$block->request) {
        $block->set_value("request", "GET /test");
    }

    if (!$block->no_error_log && !$block->error_log && !$block->must_die) {
        $block->set_value("no_error_log", "[error]\n[alert]\n[emerg]");
    }
});

run_tests;

__DATA__

=== TEST 1: marked stream servers without a session cache are registered
nginx returns early from ngx_ssl_session_ticket_keys() for a context without
a shared cache; the mark must take effect before that.
--- config
    location = /test {
        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            ngx.say(h.stream("unix:$TEST_NGINX_HTML_DIR/ctl.sock", "contexts"))
        }
    }
--- response_body
1 registered=true tickets=false keys=0
2 registered=true tickets=false keys=0
3 registered=true tickets=false keys=0



=== TEST 2: off, TLSv1.2 gets no ticket and, without a cache, no resumption
--- config
    location = /test {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            local r = assert(h.connect(a))
            ngx.say(r.protocol, " ticket: ", r.ticket,
                    ", connection tickets: ", r.conn_tickets)

            local again = assert(h.connect(a, {session = r.session}))
            ngx.say("resumed: ", again.reused)
        }
    }
--- response_body
TLSv1.2 ticket: nil, connection tickets: 0
resumed: false
--- no_error_log
apisix ssl ticket
[error]
[alert]



=== TEST 3: off, TLSv1.3 still gets its stateful ticket, which no cache keeps
--- config
    location = /test {
        lua_ssl_protocols TLSv1.3;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            local r = assert(h.connect(a))
            ngx.say(r.protocol, " ticket: ", r.ticket,
                    ", connection tickets: ", r.conn_tickets)

            local again = assert(h.connect(a, {session = r.session}))
            ngx.say("resumed: ", again.reused)
        }
    }
--- response_body
TLSv1.3 ticket: stateful, connection tickets: 0
resumed: false
--- no_error_log
apisix ssl ticket
[error]
[alert]



=== TEST 4: TLSv1.2 sessions resume across nodes that have the same keys
--- config
    location = /test {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            h.stream(ctl, "enable 1 1")
            h.stream(ctl, "enable 2 1")

            local r = assert(h.connect(a))
            ngx.say(r.protocol, " first key: ", r.ticket == h.name(1),
                    ", connection tickets: ", r.conn_tickets)

            local rb = assert(h.connect(b, {session = r.session}))
            ngx.say("on B: ", rb.reused,
                    ", same ticket: ", rb.ticket_bytes == r.ticket_bytes)

            local ra = assert(h.connect(a, {session = rb.session}))
            ngx.say("back on A: ", ra.reused)
        }
    }
--- response_body
TLSv1.2 first key: true, connection tickets: 1
on B: true, same ticket: true
back on A: true
--- error_log
apisix ssl ticket encrypt, key: "01010101010101010101010101010101" (new session)
apisix ssl ticket decrypt, key: "01010101010101010101010101010101" (default)
--- no_error_log
[error]
[alert]



=== TEST 5: TLSv1.3 sessions resume across nodes that have the same keys
--- config
    location = /test {
        lua_ssl_protocols TLSv1.3;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            h.stream(ctl, "enable 1 1")
            h.stream(ctl, "enable 2 1")

            local r = assert(h.connect(a))
            ngx.say(r.protocol, " first key: ", r.ticket == h.name(1),
                    ", connection tickets: ", r.conn_tickets)

            local rb = assert(h.connect(b, {session = r.session}))
            ngx.say("on B: ", rb.reused, ", renewed: ",
                    rb.ticket == h.name(1) and rb.ticket_bytes ~= r.ticket_bytes)

            local ra = assert(h.connect(a, {session = rb.session}))
            ngx.say("back on A: ", ra.reused)
        }
    }
--- response_body
TLSv1.3 first key: true, connection tickets: 1
on B: true, renewed: true
back on A: true
--- error_log
apisix ssl ticket encrypt, key: "01010101010101010101010101010101" (reused session)
--- no_error_log
[error]
[alert]



=== TEST 6: TLSv1.2, the first key issues, the others only decrypt
--- config
    location = /test {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            local function set(keys)
                assert(h.stream(ctl, "set_keys 1 " .. keys) == "ok")
                assert(h.stream(ctl, "set_keys 2 " .. keys) == "ok")
            end

            h.stream(ctl, "enable 1 1")
            h.stream(ctl, "enable 2 1")
            local s1 = assert(h.connect(a))

            set("2 1")
            local r = assert(h.connect(b, {session = s1.session}))
            ngx.say("history key: ", r.reused, ", renewed under 2: ",
                    r.ticket == h.name(2))

            local s2 = assert(h.connect(a))
            ngx.say("new ticket under 2: ", s2.ticket == h.name(2))

            set("1 2")
            r = assert(h.connect(b, {session = s2.session}))
            ngx.say("reordered: ", r.reused, ", renewed under 1: ",
                    r.ticket == h.name(1))

            set("2")
            r = assert(h.connect(a, {session = s1.session}))
            ngx.say("removed: ", r.reused, ", new ticket under 2: ",
                    r.ticket == h.name(2))
        }
    }
--- response_body
history key: true, renewed under 2: true
new ticket under 2: true
reordered: true, renewed under 1: true
removed: false, new ticket under 2: true
--- error_log
apisix ssl ticket decrypt, key: "01010101010101010101010101010101" not found
--- no_error_log
[error]
[alert]



=== TEST 7: TLSv1.3, the first key issues, the others only decrypt
--- config
    location = /test {
        lua_ssl_protocols TLSv1.3;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            local function set(keys)
                assert(h.stream(ctl, "set_keys 1 " .. keys) == "ok")
                assert(h.stream(ctl, "set_keys 2 " .. keys) == "ok")
            end

            h.stream(ctl, "enable 1 1")
            h.stream(ctl, "enable 2 1")
            local s1 = assert(h.connect(a))

            set("2 1")
            local r = assert(h.connect(b, {session = s1.session}))
            ngx.say("history key: ", r.reused, ", renewed under 2: ",
                    r.ticket == h.name(2))

            local s2 = assert(h.connect(a))
            ngx.say("new ticket under 2: ", s2.ticket == h.name(2))

            set("1 2")
            r = assert(h.connect(b, {session = s2.session}))
            ngx.say("reordered: ", r.reused, ", renewed under 1: ",
                    r.ticket == h.name(1))

            set("2")
            r = assert(h.connect(a, {session = s1.session}))
            ngx.say("removed: ", r.reused, ", new ticket under 2: ",
                    r.ticket == h.name(2))
        }
    }
--- response_body
history key: true, renewed under 2: true
new ticket under 2: true
reordered: true, renewed under 1: true
removed: false, new ticket under 2: true
--- error_log
apisix ssl ticket decrypt, key: "01010101010101010101010101010101" not found
--- no_error_log
[error]
[alert]



=== TEST 8: each stream server is marked and switched on its own
--- config
    location = /test {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            h.stream(ctl, "enable 1 1")
            ngx.say(h.stream(ctl, "contexts"))

            ngx.say("A: ", assert(h.connect(a)).ticket == h.name(1))
            ngx.say("B: ", assert(h.connect(b)).ticket)
        }
    }
--- response_body
1 registered=true tickets=true keys=1
2 registered=true tickets=false keys=0
3 registered=true tickets=false keys=0
A: true
B: nil



=== TEST 9: the client hello aligns a connection accepted before the switch
--- config
    location = /test {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            for _, sync in ipairs({"on", "off"}) do
                h.stream(ctl, "sync " .. sync)
                h.stream(ctl, "hold client_hello on")
                local th = ngx.thread.spawn(h.connect, a)
                h.stream_wait_held(ctl, "client_hello")

                h.stream(ctl, "enable 1 1")
                h.stream(ctl, "hold client_hello off")

                local ok, r, err = ngx.thread.wait(th)
                assert(ok and r, err)
                ngx.say("aligned: ", sync, ", ticket under 1: ",
                        r.ticket == h.name(1),
                        ", connection tickets: ", r.conn_tickets)

                h.stream(ctl, "disable 1")
            end
        }
    }
--- response_body
aligned: on, ticket under 1: true, connection tickets: 1
aligned: off, ticket under 1: false, connection tickets: 0



=== TEST 10: turned off during the handshake, the callback refuses the keys
The connection copied tickets on when it was accepted. TLSv1.2 gets an empty
ticket, then a ticket of the keys is refused at the next client hello.
--- config
    location = /test {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            h.stream(ctl, "enable 1 1")
            local s = assert(h.connect(a))

            h.stream(ctl, "hold certificate on")
            local th = ngx.thread.spawn(h.connect, a)
            h.stream_wait_held(ctl, "certificate")
            h.stream(ctl, "disable_tickets 1")
            h.stream(ctl, "hold certificate off")

            local ok, r, err = ngx.thread.wait(th)
            assert(ok and r, err)
            ngx.say("encrypt: ticket ", r.ticket,
                    ", connection tickets: ", r.conn_tickets)

            h.stream(ctl, "enable_tickets 1")
            h.stream(ctl, "sync off")
            h.stream(ctl, "hold client_hello on")
            th = ngx.thread.spawn(h.connect, a, {session = s.session})
            h.stream_wait_held(ctl, "client_hello")
            h.stream(ctl, "disable_tickets 1")
            h.stream(ctl, "hold client_hello off")

            ok, r, err = ngx.thread.wait(th)
            assert(ok and r, err)
            ngx.say("decrypt: resumed ", r.reused)
        }
    }
--- response_body
encrypt: ticket nil, connection tickets: 1
decrypt: resumed false
--- error_log
apisix ssl ticket encrypt refused, tickets are off
apisix ssl ticket decrypt refused, tickets are off
--- no_error_log
[error]
[alert]



=== TEST 11: 0 -> n -> 0 keeps an open session, new ones follow the context
--- config
    location = /test {
        lua_ssl_protocols TLSv1.3;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local lines = "unix:$TEST_NGINX_HTML_DIR/lines.sock"

            local function line(sock)
                assert(sock:send("state\n"))
                return assert(sock:receive("*l"))
            end

            local sock = ngx.socket.tcp()
            assert(sock:connect(lines))
            assert(sock:tlshandshake({server_name = "test.com"}))
            ngx.say("open: ", line(sock))

            h.stream(ctl, "enable 3 1")
            ngx.say("open: ", line(sock))

            local new = ngx.socket.tcp()
            assert(new:connect(lines))
            assert(new:tlshandshake({server_name = "test.com"}))
            ngx.say("new: ", line(new))

            h.stream(ctl, "disable 3")
            ngx.say(h.stream(ctl, "contexts"):match("3 [^\n]+"))
            ngx.say("open: ", line(sock))
            ngx.say("new: ", line(new))

            sock:close()
            new:close()
        }
    }
--- response_body
open: . TLSv1.3 0
open: . TLSv1.3 0
new: . TLSv1.3 1
3 registered=true tickets=false keys=0
open: . TLSv1.3 0
new: . TLSv1.3 1



=== TEST 12: a key that fails to encrypt fails the handshake
--- skip_eval: 2: $::NoDebug
--- config
    location = /test {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            h.stream(ctl, "enable 1 51")

            local r, err = h.connect(a)
            ngx.say("connected: ", r ~= nil)
        }
    }
--- response_body
connected: false
--- error_log
apisix ssl ticket encrypt with key "33333333333333333333333333333333" failed for the test



=== TEST 13: an unmarked stream server keeps the native keys
--- config
    location = /test {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ctl = "unix:$TEST_NGINX_HTML_DIR/ctl.sock"
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local native = "unix:$TEST_NGINX_HTML_DIR/native.sock"

            h.stream(ctl, "enable 1 1")

            local n = assert(h.connect(native))
            ngx.say("native ticket: ", n.ticket ~= nil
                    and n.ticket ~= "stateful" and n.ticket ~= h.name(1),
                    ", connection: ", n.conn_tickets)

            local r = assert(h.connect(native, {session = n.session}))
            ngx.say("resumes its own: ", r.reused)

            r = assert(h.connect(a, {session = n.session}))
            ngx.say("A takes it: ", r.reused)

            local s = assert(h.connect(a))
            r = assert(h.connect(native, {session = s.session}))
            ngx.say("takes the ticket of A: ", r.reused)
        }
    }
--- response_body
native ticket: true, connection: not_marked
resumes its own: true
A takes it: false
takes the ticket of A: false



=== TEST 14: the mark is not allowed in stream{}
--- stream_config
    apisix_ssl_session_ticket_takeover on;
--- config
    location = /test {
        return 200;
    }
--- must_die
--- error_log
"apisix_ssl_session_ticket_takeover" directive is not allowed here



=== TEST 15: in init_by_lua, the contexts are not registered for the process yet
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/a.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        apisix_ssl_session_ticket_takeover on;
        return unused;
    }

    init_by_lua_block {
        local ticket = require("resty.apisix.ssl_session_ticket")
        local ctx = assert(ticket.contexts())[1]
        ngx.log(ngx.WARN, "stream context in init: registered=",
                ctx.registered)
    }
--- config
    location = /test {
        return 200 "ok\n";
    }
--- response_body
ok
--- error_log
stream context in init: registered=false
