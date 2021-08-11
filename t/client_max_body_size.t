use t::APISIX_NGINX 'no_plan';

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->http_config) {
        my $http_config = <<'_EOC_';
    apisix_delay_client_max_body_check on;
_EOC_

        $block->set_value("http_config", $http_config);
    }
});

run_tests;

__DATA__

=== TEST 1: global client_max_body_size set
--- config
    location /t {
        client_max_body_size 1;
        return 200;
    }
--- request
POST /t
1234



=== TEST 2: global client_max_body_size set, without check delay
--- config
    apisix_delay_client_max_body_check off;
    location /t {
        client_max_body_size 1;
        return 200;
    }
--- request
POST /t
1234
--- error_code: 413
--- error_log
client intended to send too large body



=== TEST 3: set client_max_body_size
--- config
    location /t {
        client_max_body_size 1;
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_client_max_body_size(5))
        }
        content_by_lua_block {
            ngx.req.read_body()
            ngx.exit(200)
        }
    }
--- request
POST /t
1234



=== TEST 4: set client_max_body_size, failed
--- config
    location /t {
        client_max_body_size 1;
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_client_max_body_size(2))
        }
        content_by_lua_block {
            ngx.req.read_body()
            ngx.exit(200)
        }
    }
--- request
POST /t
1234
--- error_code: 413
--- error_log
client intended to send too large body



=== TEST 5: set client_max_body_size, chunked
--- config
    location /t {
        client_max_body_size 1;
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_client_max_body_size(5))
        }
        content_by_lua_block {
            ngx.req.read_body()
            ngx.exit(200)
        }
    }
--- raw_request eval
qq{POST /t HTTP/1.1\r
Host: localhost\r
Transfer-Encoding: chunked\r
Connection: close\r
\r
5\r
Hello\r
0\r
\r
}



=== TEST 6: set client_max_body_size, failed
--- config
    location /t {
        client_max_body_size 1;
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_client_max_body_size(4))
        }
        content_by_lua_block {
            ngx.req.read_body()
            ngx.exit(200)
        }
    }
--- raw_request eval
qq{POST /t HTTP/1.1\r
Host: localhost\r
Transfer-Encoding: chunked\r
Connection: close\r
\r
5\r
Hello\r
0\r
\r
}
--- error_code: 413
--- error_log
client intended to send too large chunked body



=== TEST 7: set client_max_body_size, http2
--- config
    location /t {
        client_max_body_size 1;
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_client_max_body_size(125))
        }
        content_by_lua_block {
            ngx.req.read_body()
            ngx.exit(200)
        }
    }
--- more_headers
Transfer-Encoding: chunked
--- request eval
qq{POST /t
5\r
Hello\r
0\r
\r
}
--- use_http2



=== TEST 8: set client_max_body_size, http2, failed
--- config
    location /t {
        client_max_body_size 1;
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_client_max_body_size(1))
        }
        content_by_lua_block {
            ngx.req.read_body()
            ngx.exit(200)
        }
    }
--- more_headers
Transfer-Encoding: chunked
--- request eval
qq{POST /t
11\r
Hello World\r
0\r
\r
}
--- use_http2
--- error_code: 413
--- error_log
client intended to send too large chunked body



=== TEST 9: set client_max_body_size, proxy pass
--- config
    location /up {
        return 200;
    }
    location /t {
        client_max_body_size 1;
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_client_max_body_size(5))
        }
        proxy_pass http://127.0.0.1:1984/up;
    }
--- request
POST /t
1234



=== TEST 10: set client_max_body_size, proxy pass, failed
--- config
    location /up {
        return 200;
    }
    location /t {
        client_max_body_size 1;
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_client_max_body_size(3))
        }
        proxy_pass http://127.0.0.1:1984/up;
    }
--- request
POST /t
1234
--- error_code: 413
--- error_log
client intended to send too large body



=== TEST 11: set client_max_body_size to 0 means no limitation
--- config
    location /up {
        return 200;
    }
    location /t {
        client_max_body_size 1;
        access_by_lua_block {
            local client = require("resty.apisix.client")
            assert(client.set_client_max_body_size(0))
        }
        proxy_pass http://127.0.0.1:1984/up;
    }
--- request
POST /t
1234
