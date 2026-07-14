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

run_tests();

__DATA__

=== TEST 1: move rejects a source socket with a pending read
--- stream_config
    server {
        listen 1995;
        content_by_lua_block {
            local sk = assert(ngx.req.socket(true))
            assert(sk:send("AAAA"))
            ngx.sleep(0.1)
            assert(sk:send("BBBB"))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local xrpc = require("resty.apisix.stream.xrpc.socket")
        local src = xrpc.upstream.socket()
        src:settimeout(1000)
        assert(src:connect("127.0.0.1", 1995))

        local th = ngx.thread.spawn(function()
            local p, err = src:read(8)
            if p then
                ngx.log(ngx.WARN, "read result hex: ",
                        require("resty.string").to_hex(ffi.string(p, 8)))
            else
                ngx.log(ngx.WARN, "read error: ", err)
            end
        end)

        ngx.sleep(0.02)
        local dst = xrpc.downstream.socket()
        local ok, err = dst:move(src)
        ngx.log(ngx.WARN, "move result: ", ok, ", ", err)
        assert(ngx.thread.wait(th))
    }
--- stream_request
--- stream_response
--- grep_error_log eval
qr/(?:move result: nil, socket busy reading|read result hex: [0-9a-f]+)/
--- grep_error_log_out
move result: nil, socket busy reading
read result hex: 4141414142424242



=== TEST 2: reset_read_buf rejects a socket with a pending read
--- stream_config
    server {
        listen 1996;
        content_by_lua_block {
            local sk = assert(ngx.req.socket(true))
            assert(sk:send("AAAA"))
            ngx.sleep(0.1)
            assert(sk:send("BBBB"))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local ffi = require("ffi")
        local xrpc = require("resty.apisix.stream.xrpc.socket")
        local src = xrpc.upstream.socket()
        src:settimeout(1000)
        assert(src:connect("127.0.0.1", 1996))

        local th = ngx.thread.spawn(function()
            local p, err = src:read(8)
            if p then
                ngx.log(ngx.WARN, "read result hex: ",
                        require("resty.string").to_hex(ffi.string(p, 8)))
            else
                ngx.log(ngx.WARN, "read error: ", err)
            end
        end)

        ngx.sleep(0.02)
        local ok, err = src:reset_read_buf()
        ngx.log(ngx.WARN, "reset result: ", ok, ", ", err)
        assert(ngx.thread.wait(th))
    }
--- stream_request
--- stream_response
--- grep_error_log eval
qr/(?:reset result: nil, socket busy reading|read result hex: [0-9a-f]+)/
--- grep_error_log_out
reset result: nil, socket busy reading
read result hex: 4141414142424242



=== TEST 3: reset_read_buf recycles every receive buffer
--- stream_server_config
    lua_socket_buffer_size 128;
    content_by_lua_block {
        local sk = require("resty.apisix.stream.xrpc.socket").downstream.socket()
        sk:settimeout(1000)

        for _ = 1, 10 do
            assert(sk:read(128))
            assert(sk:read(128))
            assert(sk:read(128))
            assert(sk:reset_read_buf())
        end

        ngx.say("ok")
    }
--- stream_request eval
"x" x (128 * 3 * 10)
--- stream_response
ok
--- grep_error_log eval
qr/lua allocate new chainlink and new buf of size 128/
--- grep_error_log_out eval
("lua allocate new chainlink and new buf of size 128\n" x 3)



=== TEST 4: move still works on an idle source socket
--- stream_config
    server {
        listen 1997;
        content_by_lua_block {
            local sk = assert(ngx.req.socket(true))
            assert(sk:send("AAAABBBB"))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local xrpc = require("resty.apisix.stream.xrpc.socket")
        local src = xrpc.upstream.socket()
        src:settimeout(1000)
        assert(src:connect("127.0.0.1", 1997))

        assert(src:read(8))

        local dst = xrpc.downstream.socket()
        assert(dst:move(src))
    }
--- stream_request
--- stream_response eval
"AAAABBBB"
