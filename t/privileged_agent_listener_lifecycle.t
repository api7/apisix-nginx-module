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

use IO::Socket::INET;
use t::APISIX_NGINX $SkipReason
    ? (skip_all => $SkipReason)
    : ('no_plan');

# reserve the port used by TEST 1 so that the privileged agent listener
# cannot bind it
our $blocker = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => 19091,
    Listen    => 5,
    ReuseAddr => 1,
) or die "failed to reserve 127.0.0.1:19091: $!";

master_on();
run_tests();

__DATA__

=== TEST 1: startup fails when a privileged-agent listener cannot bind
The master process owns every listening socket, so an unavailable
privileged agent address must abort startup instead of leaving a
healthy-looking master without the listener.
--- http_config
init_by_lua_block {
    local process = require "ngx.process"
    assert(process.enable_privileged_agent())
}
server {
    listen 127.0.0.1:19091 enable_process=privileged_agent;
    location / {
        return 200 "privileged\n";
    }
}
--- config
    location /t {
        return 200 "worker\n";
    }
--- must_die
--- error_log
bind() to 127.0.0.1:19091 failed



=== TEST 2: socket options are applied to the privileged agent listener
The master configures the real fd, so rcvbuf must not hit
"setsockopt(...) failed (9: Bad file descriptor)" (would show up as an
[alert] in the error log) and the listener must serve requests.
--- http_config
init_by_lua_block {
    local process = require "ngx.process"
    assert(process.enable_privileged_agent())
}
server {
    listen 127.0.0.1:19093 rcvbuf=64k enable_process=privileged_agent;
    location / {
        return 200 "privileged";
    }
}
--- config
    location /t {
        content_by_lua_block {
            local httpc = ngx.socket.tcp()
            assert(httpc:connect("127.0.0.1", 19093))
            assert(httpc:send("GET / HTTP/1.0\r\nHost: t\r\n\r\n"))
            local resp = httpc:receive("*a")
            httpc:close()
            ngx.say(resp:match("privileged") or "no body")
        }
    }
--- response_body
privileged



=== TEST 3: privileged agent listener is closed when the agent is disabled
Nothing will accept on the listener, so the master closes it and
clients get "connection refused" instead of hanging in the accept
backlog.
--- http_config
server {
    listen 127.0.0.1:19094 enable_process=privileged_agent;
    location / {
        return 200 "privileged";
    }
}
--- config
    location /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            local ok, err = sock:connect("127.0.0.1", 19094)
            ngx.say("connect: ", ok, ", ", err)
            sock:close()
        }
    }
--- response_body
connect: nil, connection refused
--- error_log
connect() failed (111: Connection refused)
--- no_error_log
[alert]
