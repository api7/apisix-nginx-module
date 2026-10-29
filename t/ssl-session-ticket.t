our ($SkipReason, $NoDebug);

BEGIN {
    # test keys 51 and 52 fail as if the crypto library failed, the first to
    # encrypt a ticket and the other to decrypt one: a debug build only
    $ENV{APISIX_TEST_SSL_SESSION_TICKET_FAIL_ENCRYPT} = "33" x 16;
    $ENV{APISIX_TEST_SSL_SESSION_TICKET_FAIL_DECRYPT} = "34" x 16;

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

    # nodes A and B stand for two gateways of a cluster: the same
    # certificate, nothing else in common
    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    server {
        listen unix:$TEST_NGINX_HTML_DIR/a.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        # shared with the unmarked server below, like the Admin API does
        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;
        apisix_ssl_session_ticket_takeover on;

        ssl_client_hello_by_lua_block {
            require("t.lib.ssl_session_ticket").client_hello()
        }

        ssl_certificate_by_lua_block {
            require("t.lib.ssl_session_ticket").certificate()
        }

        location / {
            content_by_lua_block {
                require("t.lib.ssl_session_ticket").respond()
            }
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

        location / {
            content_by_lua_block {
                require("t.lib.ssl_session_ticket").respond()
            }
        }
    }

    # not marked, like the Admin API: native keys from the shared cache
    server {
        listen unix:$TEST_NGINX_HTML_DIR/admin.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets on;

        location / {
            content_by_lua_block {
                require("t.lib.ssl_session_ticket").respond()
            }
        }
    }
_EOC_

        $block->set_value("http_config", $http_config);
    }

    if (!$block->no_error_log && !$block->error_log && !$block->must_die) {
        $block->set_value("no_error_log", "[error]\n[alert]\n[emerg]");
    }
});

run_tests;

__DATA__

=== TEST 1: the marked servers are registered, and start without tickets
Node B leaves ssl_session_tickets at its native default (on), the mark still
starts its context off. The unmarked server is not listed.
--- config
    location = /t {
        content_by_lua_block {
            local ticket = require("resty.apisix.ssl_session_ticket")
            local ctxs = assert(ticket.contexts())
            for _, ctx in ipairs(ctxs) do
                ngx.say(ctx.id, " registered=", ctx.registered,
                        " tickets=", ctx.tickets, " keys=", ctx.keys,
                        " generation=", ctx.generation,
                        " conf=", (ctx.conf:gsub("^.*/", "")
                                           :gsub(":%d+$", ":N")))
            end
        }
    }
--- response_body
1 registered=true tickets=false keys=0 generation=1 conf=nginx.conf:N
2 registered=true tickets=false keys=0 generation=1 conf=nginx.conf:N



=== TEST 2: off, TLSv1.2 gets no ticket, only a session id the node caches
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            local r = assert(h.connect(a, {http = true}))
            ngx.say(r.protocol, " ticket: ", r.ticket,
                    ", connection tickets: ", r.conn_tickets)

            local same = assert(h.connect(a, {http = true, session = r.session}))
            ngx.say("same node: ", same.reused)

            local other = assert(h.connect(b, {http = true, session = r.session}))
            ngx.say("other node: ", other.reused)
        }
    }
--- response_body
TLSv1.2 ticket: nil, connection tickets: 0
same node: true
other node: false
--- no_error_log
apisix ssl ticket
[error]
[alert]



=== TEST 3: off, TLSv1.3 still gets the stateful ticket of the session cache
--- config
    location = /t {
        lua_ssl_protocols TLSv1.3;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            local r = assert(h.connect(a, {http = true}))
            ngx.say(r.protocol, " ticket: ", r.ticket,
                    ", connection tickets: ", r.conn_tickets)

            local same = assert(h.connect(a, {http = true, session = r.session}))
            ngx.say("same node: ", same.reused)

            local other = assert(h.connect(b, {http = true, session = r.session}))
            ngx.say("other node: ", other.reused)
        }
    }
--- response_body
TLSv1.3 ticket: stateful, connection tickets: 0
same node: true
other node: false
--- no_error_log
apisix ssl ticket
[error]
[alert]



=== TEST 4: TLSv1.2 sessions resume across nodes that have the same keys
A ticket under the first key resumes without a new ticket: the callback
returns 1, not renew.
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            h.enable(1, 1)
            h.enable(2, 1)

            local r = assert(h.connect(a, {http = true}))
            ngx.say(r.protocol, " first key: ", r.ticket == h.name(1),
                    ", connection tickets: ", r.conn_tickets)

            local rb = assert(h.connect(b, {http = true, session = r.session}))
            ngx.say("on B: ", rb.reused,
                    ", same ticket: ", rb.ticket_bytes == r.ticket_bytes)

            local ra = assert(h.connect(a, {http = true, session = rb.session}))
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
TLSv1.3 renews the ticket on every resumption, as nginx does.
--- config
    location = /t {
        lua_ssl_protocols TLSv1.3;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            h.enable(1, 1)
            h.enable(2, 1)

            local r = assert(h.connect(a, {http = true}))
            ngx.say(r.protocol, " first key: ", r.ticket == h.name(1),
                    ", connection tickets: ", r.conn_tickets)

            local rb = assert(h.connect(b, {http = true, session = r.session}))
            ngx.say("on B: ", rb.reused, ", renewed: ",
                    rb.ticket == h.name(1) and rb.ticket_bytes ~= r.ticket_bytes)

            local ra = assert(h.connect(a, {http = true, session = rb.session}))
            ngx.say("back on A: ", ra.reused)
        }
    }
--- response_body
TLSv1.3 first key: true, connection tickets: 1
on B: true, renewed: true
back on A: true
--- error_log
apisix ssl ticket encrypt, key: "01010101010101010101010101010101" (new session)
apisix ssl ticket encrypt, key: "01010101010101010101010101010101" (reused session)
apisix ssl ticket decrypt, key: "01010101010101010101010101010101" (default)
--- no_error_log
[error]
[alert]



=== TEST 6: TLSv1.2, the first key issues, the others only decrypt
Rotate, reorder and remove, the way a complete set is replaced each time.
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            local function set(...)
                assert(ticket.set_keys(1, h.keys(...)))
                assert(ticket.set_keys(2, h.keys(...)))
            end

            h.enable(1, 1)
            h.enable(2, 1)
            local s1 = assert(h.connect(a, {http = true}))

            -- rotation: 2 issues, 1 still decrypts
            set(2, 1)
            local r = assert(h.connect(b, {http = true, session = s1.session}))
            ngx.say("history key: ", r.reused, ", renewed under 2: ",
                    r.ticket == h.name(2))

            local s2 = assert(h.connect(a, {http = true}))
            ngx.say("new ticket under 2: ", s2.ticket == h.name(2))

            -- reorder: 1 issues again, 2 decrypts
            set(1, 2)
            r = assert(h.connect(b, {http = true, session = s2.session}))
            ngx.say("reordered: ", r.reused, ", renewed under 1: ",
                    r.ticket == h.name(1))

            -- remove 1: its tickets no longer resume, the handshake completes
            set(2)
            r = assert(h.connect(a, {http = true, session = s1.session}))
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
apisix ssl ticket decrypt, key: "01010101010101010101010101010101"
apisix ssl ticket decrypt, key: "02020202020202020202020202020202"
apisix ssl ticket decrypt, key: "01010101010101010101010101010101" not found
--- no_error_log
[error]
[alert]



=== TEST 7: TLSv1.3, the first key issues, the others only decrypt
--- config
    location = /t {
        lua_ssl_protocols TLSv1.3;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            local function set(...)
                assert(ticket.set_keys(1, h.keys(...)))
                assert(ticket.set_keys(2, h.keys(...)))
            end

            h.enable(1, 1)
            h.enable(2, 1)
            local s1 = assert(h.connect(a, {http = true}))

            set(2, 1)
            local r = assert(h.connect(b, {http = true, session = s1.session}))
            ngx.say("history key: ", r.reused, ", renewed under 2: ",
                    r.ticket == h.name(2))

            local s2 = assert(h.connect(a, {http = true}))
            ngx.say("new ticket under 2: ", s2.ticket == h.name(2))

            set(1, 2)
            r = assert(h.connect(b, {http = true, session = s2.session}))
            ngx.say("reordered: ", r.reused, ", renewed under 1: ",
                    r.ticket == h.name(1))

            set(2)
            r = assert(h.connect(a, {http = true, session = s1.session}))
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



=== TEST 8: turned off while a TLSv1.2 handshake runs, the empty ticket
The connection copied tickets on when it was accepted; the context is turned
off before the ticket is encrypted. The callback refuses, so OpenSSL sends a
zero-length ticket, and the handshake completes.
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            h.enable(1, 1)

            h.hold.certificate = true
            local th = ngx.thread.spawn(h.connect, a, {http = true})
            h.wait_held("certificate")

            assert(ticket.disable_tickets(1))
            h.hold.certificate = nil

            local ok, r, err = ngx.thread.wait(th)
            assert(ok and r, err)
            ngx.say(r.protocol, " ticket: ", r.ticket,
                    ", connection tickets: ", r.conn_tickets)
        }
    }
--- response_body
TLSv1.2 ticket: nil, connection tickets: 1
--- error_log
apisix ssl ticket encrypt refused, tickets are off
--- no_error_log
[error]
[alert]



=== TEST 9: turned off while a TLSv1.3 handshake runs, no ticket at all
--- config
    location = /t {
        lua_ssl_protocols TLSv1.3;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            h.enable(1, 1)

            h.hold.certificate = true
            local th = ngx.thread.spawn(h.connect, a, {http = true})
            h.wait_held("certificate")

            assert(ticket.disable_tickets(1))
            h.hold.certificate = nil

            local ok, r, err = ngx.thread.wait(th)
            assert(ok and r, err)
            ngx.say(r.protocol, " ticket: ", r.ticket,
                    ", connection tickets: ", r.conn_tickets)
        }
    }
--- response_body
TLSv1.3 ticket: nil, connection tickets: 1
--- error_log
apisix ssl ticket encrypt refused, tickets are off
--- no_error_log
[error]
[alert]



=== TEST 10: turned off before a TLSv1.2 ticket is decrypted, no resumption
The keys are still installed, the connection was not aligned: the callback
refuses the ticket on its own, which costs a full handshake.
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            h.enable(1, 1)
            h.enable(2, 1)
            local s = assert(h.connect(a, {http = true}))

            h.sync = false
            h.hold.client_hello = true
            local th = ngx.thread.spawn(h.connect, b,
                                        {http = true, session = s.session})
            h.wait_held("client_hello")

            assert(ticket.disable_tickets(2))
            h.hold.client_hello = nil

            local ok, r, err = ngx.thread.wait(th)
            assert(ok and r, err)
            ngx.say("reused: ", r.reused, ", ticket: ", r.ticket)
        }
    }
--- response_body
reused: false, ticket: nil
--- error_log
apisix ssl ticket decrypt refused, tickets are off
--- no_error_log
[error]
[alert]



=== TEST 11: turned off before a TLSv1.3 ticket is decrypted, no resumption
--- config
    location = /t {
        lua_ssl_protocols TLSv1.3;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local b = "unix:$TEST_NGINX_HTML_DIR/b.sock"

            h.enable(1, 1)
            h.enable(2, 1)
            local s = assert(h.connect(a, {http = true}))

            h.sync = false
            h.hold.client_hello = true
            local th = ngx.thread.spawn(h.connect, b,
                                        {http = true, session = s.session})
            h.wait_held("client_hello")

            assert(ticket.disable_tickets(2))
            h.hold.client_hello = nil

            local ok, r, err = ngx.thread.wait(th)
            assert(ok and r, err)
            ngx.say("reused: ", r.reused, ", ticket: ", r.ticket)
        }
    }
--- response_body
reused: false, ticket: nil
--- error_log
apisix ssl ticket decrypt refused, tickets are off
apisix ssl ticket encrypt refused, tickets are off
--- no_error_log
[error]
[alert]



=== TEST 12: the client hello aligns a connection accepted before the switch
SSL_new() copied tickets off; the context is turned on while the handshake
waits in the client hello. Aligned, the connection gets a ticket; left alone,
it keeps the options it was created with.
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            for _, sync in ipairs({true, false}) do
                h.sync = sync
                h.hold.client_hello = true
                local th = ngx.thread.spawn(h.connect, a, {http = true})
                h.wait_held("client_hello")

                h.enable(1, 1)
                h.hold.client_hello = nil

                local ok, r, err = ngx.thread.wait(th)
                assert(ok and r, err)
                ngx.say("aligned: ", sync, ", ticket under 1: ",
                        r.ticket == h.name(1),
                        ", connection tickets: ", r.conn_tickets)

                h.disable(1)
            end
        }
    }
--- response_body
aligned: true, ticket under 1: true, connection tickets: 1
aligned: false, ticket under 1: false, connection tickets: 0
--- no_error_log
[error]
[alert]



=== TEST 13: 0 -> n -> 0 keeps an open connection, new ones follow the context
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            local function state()
                local ctx = assert(ticket.contexts())[1]
                return "tickets=" .. tostring(ctx.tickets)
                       .. " keys=" .. ctx.keys
            end

            local sock = ngx.socket.tcp()
            assert(sock:connect(a))
            assert(sock:tlshandshake({server_name = "test.com"}))
            ngx.say("open: ", h.request(sock))

            h.enable(1, 1)
            ngx.say("on: ", state())
            ngx.say("open: ", h.request(sock))
            local r = assert(h.connect(a, {http = true}))
            ngx.say("new: ticket under 1: ", r.ticket == h.name(1),
                    ", connection tickets: ", r.conn_tickets)

            assert(ticket.disable_tickets(1))
            ngx.say("disabled: ", state())
            assert(ticket.revoke_keys(1))
            ngx.say("revoked: ", state())
            ngx.say("open: ", h.request(sock))
            r = assert(h.connect(a, {http = true}))
            ngx.say("new: ticket: ", r.ticket,
                    ", connection tickets: ", r.conn_tickets)

            sock:close()
        }
    }
--- response_body
open: . TLSv1.2 0
on: tickets=true keys=1
open: . TLSv1.2 0
new: ticket under 1: true, connection tickets: 1
disabled: tickets=false keys=1
revoked: tickets=false keys=0
open: . TLSv1.2 0
new: ticket: nil, connection tickets: 0
--- no_error_log
[error]
[alert]



=== TEST 14: a key that fails to encrypt fails the handshake
The callback returns a negative value, which OpenSSL takes as fatal rather
than as no ticket.
--- skip_eval: 3: $::NoDebug
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            h.enable(1, 51)

            local r, err = h.connect(a, {http = true})
            ngx.say("connected: ", r ~= nil)
        }
    }
--- response_body
connected: false
--- error_log
apisix ssl ticket encrypt with key "33333333333333333333333333333333" failed for the test



=== TEST 15: a key that fails to decrypt fails the handshake
--- skip_eval: 3: $::NoDebug
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"

            h.enable(1, 52)

            local s = assert(h.connect(a, {http = true}))
            ngx.say("ticket under 52: ", s.ticket == h.name(52))

            local r, err = h.connect(a, {http = true, session = s.session})
            ngx.say("resumed: ", r ~= nil)
        }
    }
--- response_body
ticket under 52: true
resumed: false
--- error_log
apisix ssl ticket decrypt with key "34343434343434343434343434343434" failed for the test



=== TEST 16: an unmarked server keeps the native keys of its shared cache
It shares the session cache of node A, as the Admin API shares it with the
data plane. Its tickets come from the native keys of the cache, which A
neither uses nor accepts, and the other way around.
--- config
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")
            local a = "unix:$TEST_NGINX_HTML_DIR/a.sock"
            local admin = "unix:$TEST_NGINX_HTML_DIR/admin.sock"

            h.enable(1, 1)

            local adm = assert(h.connect(admin, {http = true}))
            ngx.say("native ticket: ", adm.ticket ~= nil
                    and adm.ticket ~= "stateful" and adm.ticket ~= h.name(1),
                    ", connection: ", adm.conn_tickets)

            local again = assert(h.connect(admin, {http = true}))
            ngx.say("same native key: ", again.ticket == adm.ticket)

            local r = assert(h.connect(admin, {http = true, session = adm.session}))
            ngx.say("resumes its own: ", r.reused)

            r = assert(h.connect(a, {http = true, session = adm.session}))
            ngx.say("A takes it: ", r.reused)

            local s = assert(h.connect(a, {http = true}))
            r = assert(h.connect(admin, {http = true, session = s.session}))
            ngx.say("takes the ticket of A: ", r.reused)

            ngx.say("contexts: ", #assert(ticket.contexts()))
        }
    }
--- response_body
native ticket: true, connection: not_marked
same native key: true
resumes its own: true
A takes it: false
takes the ticket of A: false
contexts: 2
--- error_log eval
qr/#\d+: \*\d+ ssl ticket encrypt, key: "[0-9a-f]{32}" \(new session\)/
--- no_error_log
[error]
[alert]



=== TEST 17: the mark is not allowed in http{}
--- http_config
    apisix_ssl_session_ticket_takeover on;
--- config
    location = /t {
        return 200;
    }
--- must_die
--- error_log
"apisix_ssl_session_ticket_takeover" directive is not allowed here



=== TEST 18: a marked server cannot have ssl_session_ticket_key
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/a.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        ssl_session_ticket_key ticket.key;
        apisix_ssl_session_ticket_takeover on;
    }
--- config
    location = /t {
        return 200;
    }
--- must_die
--- error_log
"ssl_session_ticket_key" cannot be used in a server with "apisix_ssl_session_ticket_takeover" on



=== TEST 19: invalid calls change nothing
--- config
    location = /t {
        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local ticket = require("resty.apisix.ssl_session_ticket")

            local function say(res, err)
                ngx.say(tostring(res), " ", tostring(err))
            end

            say(ticket.set_keys(3, h.keys(1)))
            say(ticket.set_keys(0, h.keys(1)))
            say(ticket.set_keys("1", h.keys(1)))
            say(ticket.enable_tickets(1))
            say(ticket.set_keys(1, {}))
            say(ticket.set_keys(1, "keys"))
            say(ticket.set_keys(1, {h.key(1), "short"}))

            local many = {}
            for i = 1, ticket.MAX_KEYS + 1 do
                many[i] = h.key(1)
            end
            say(ticket.set_keys(1, many))

            say(ticket.set_keys(1, h.keys(1, 2)))
            -- the same name with other secrets
            say(ticket.set_keys(1, {h.key(3), h.key(3):sub(1, 16) .. h.key(4):sub(17)}))
            ngx.say("kept: ", assert(ticket.contexts())[1].keys)

            many = {}
            for i = 1, ticket.MAX_KEYS do
                many[i] = string.format("%016d", i) .. h.key(1):sub(17)
            end
            say(ticket.set_keys(1, many))

            say(ticket.enable_tickets(1))
            say(ticket.revoke_keys(1))
            local ctx = assert(ticket.contexts())[1]
            ngx.say("revoked: tickets=", ctx.tickets, " keys=", ctx.keys)
            say(ticket.enable_tickets(1))
            say(ticket.disable_tickets(1))

            -- the connection calls need a TLS connection
            say(ticket.sync_connection())
            say(ticket.connection_tickets())
        }
    }
--- response_body
nil no_context
nil no_context
nil no_context
nil no_keys
nil invalid_keys: not a non-empty array of keys
nil invalid_keys: not a non-empty array of keys
nil invalid_keys: key 2 is not 80 bytes
nil invalid_keys: too many keys
true nil
nil invalid_keys: duplicate key name
kept: 2
true nil
true nil
true nil
revoked: tickets=false keys=0
nil no_keys
true nil
nil no_ssl
nil no_ssl



=== TEST 20: the calls outside of a TLS request
In init_by_lua*, the configuration being loaded is not committed yet: its
contexts are listed, and do not verify for the generation of the process.
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/a.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        apisix_ssl_session_ticket_takeover on;
    }

    init_by_lua_block {
        local ticket = require("resty.apisix.ssl_session_ticket")
        local ok, err = ticket.sync_connection()
        ngx.log(ngx.WARN, "in init: ", ok, " ", err)

        local ctx = assert(ticket.contexts())[1]
        ngx.log(ngx.WARN, "context in init: registered=", ctx.registered)
        ok, err = ticket.set_keys(1, {string.rep("k", 80)})
        ngx.log(ngx.WARN, "set_keys in init: ", ok, " ", err)
    }
--- config
    location = /t {
        content_by_lua_block {
            local ticket = require("resty.apisix.ssl_session_ticket")

            ngx.timer.at(0, function ()
                local ok, err = ticket.sync_connection()
                ngx.log(ngx.WARN, "in a timer: ", ok, " ", err)
            end)

            ngx.sleep(0.01)
            ngx.say("ok")
        }
    }
--- response_body
ok
--- error_log
in init: nil no_request
context in init: registered=false
set_keys in init: nil not_registered
in a timer: nil no_ssl
