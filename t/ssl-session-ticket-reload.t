our $SkipReason;

BEGIN {
    # every block after the first one reloads nginx, which commits a new
    # configuration generation
    $ENV{TEST_NGINX_USE_HUP} = 1;

    my $nginx_binary = $ENV{'TEST_NGINX_BINARY'} || 'nginx';
    my $version = eval { `$nginx_binary -V 2>&1` } // '';
    if ($version !~ m{openresty/1\.31\.1\.}) {
        # the takeover patch only exists for this bundle
        $SkipReason = "the session ticket takeover needs OpenResty 1.31.1";
    }
}

use t::APISIX_NGINX $SkipReason
    ? (skip_all => $SkipReason)
    : ('no_plan');

master_on();
repeat_each(1);

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    lua_shared_dict identity 1m;

    init_by_lua_block {
        assert(require("ngx.process").enable_privileged_agent())
    }

    init_worker_by_lua_block {
        local id = assert(require("resty.apisix.process").get_identity())
        if id.type == "privileged agent" then
            ngx.shared.identity:set("agent " .. id.generation,
                                    tostring(id.worker_id) .. " slot="
                                    .. id.slot .. " pid="
                                    .. tostring(id.pid == ngx.worker.pid()))
        end
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/a.sock ssl;
        ssl_certificate ../../certs/test.crt;
        ssl_certificate_key ../../certs/test.key;
        apisix_ssl_session_ticket_takeover on;

        location / {
            content_by_lua_block {
                require("t.lib.ssl_session_ticket").respond()
            }
        }
    }
_EOC_

        $block->set_value("http_config", $http_config);
    }

    if (!$block->config) {
        my $config = <<'_EOC_';
    location = /t {
        lua_ssl_protocols TLSv1.2;

        content_by_lua_block {
            local h = require("t.lib.ssl_session_ticket")
            local process = require("resty.apisix.process")
            local ticket = require("resty.apisix.ssl_session_ticket")

            local id = assert(process.get_identity())
            ngx.say(id.type, " worker_id=", id.worker_id, " slot=", id.slot,
                    " count=", id.worker_count, " pid=",
                    id.pid == ngx.worker.pid(), " generation=", id.generation)

            ngx.say("privileged agent: worker_id=",
                    ngx.shared.identity:get("agent " .. id.generation))

            -- the record of the registration belongs to this generation
            local ctx = assert(ticket.contexts())[1]
            ngx.say("context generation=", ctx.generation,
                    " registered=", ctx.registered)

            h.enable(1, 1)
            local r = assert(h.connect("unix:$TEST_NGINX_HTML_DIR/a.sock",
                                       {http = true}))
            ngx.say("ticket under 1: ", r.ticket == h.name(1))
        }
    }
_EOC_

        $block->set_value("config", $config);
    }
});

run_tests;

__DATA__

=== TEST 1: the first configuration is generation 1
--- response_body
worker worker_id=0 slot=0 count=1 pid=true generation=1
privileged agent: worker_id=nil slot=1 pid=true
context generation=1 registered=true
ticket under 1: true



=== TEST 2: a reload starts generation 2, with its registrations
--- response_body
worker worker_id=0 slot=0 count=1 pid=true generation=2
privileged agent: worker_id=nil slot=1 pid=true
context generation=2 registered=true
ticket under 1: true
