use t::APISIX_NGINX 'no_plan';

no_root_location();
run_tests;

__DATA__

=== TEST 1: validate session ticket snapshots and unsupported builds
--- config
location /t {
    content_by_lua_block {
        local tickets = require("resty.apisix.ssl_session_ticket")
        assert(type(tickets.is_supported()) == "boolean")
        if not tickets.is_supported() then
            local ok, err = tickets.set_keys({})
            assert(not ok and err == "native session ticket hook unavailable in this build")
            ngx.say("snapshot API passed")
            return
        end

        local function key()
            return {
                key = string.rep("a", 80),
                encrypt_from = 1,
                encrypt_until = 9007199254740990,
                decrypt_until = 9007199254740991,
                lifetime = 300,
            }
        end

        assert(tickets.set_keys({key()}))
        local ok, err = tickets.set_keys({key(), key()})
        assert(not ok and err == "duplicate session ticket key name")

        for _, input in ipairs({false, "invalid", {key = key()}, {[2] = key()}}) do
            assert(not tickets.set_keys(input))
        end
        for _, length in ipairs({0, 48, 79, 81}) do
            local input = key()
            input.key = string.rep("a", length)
            assert(not tickets.set_keys({input}))
        end
        for _, lifetime in ipairs({0, 604801, 1.5, math.huge, 0 / 0}) do
            local input = key()
            input.lifetime = lifetime
            assert(not tickets.set_keys({input}))
        end
        for _, field in ipairs({"encrypt_from", "encrypt_until", "decrypt_until"}) do
            local input = key()
            input[field] = -1
            assert(not tickets.set_keys({input}))
            input[field] = 9007199254740992
            assert(not tickets.set_keys({input}))
        end
        local input = key()
        input.encrypt_from = input.encrypt_until
        assert(not tickets.set_keys({input}))
        input = key()
        input.decrypt_until = input.encrypt_until
        assert(not tickets.set_keys({input}))

        local oversized = {}
        for position = 1, 257 do
            oversized[position] = key()
        end
        assert(not tickets.set_keys(oversized))
        assert(tickets.expire_keys())
        assert(tickets.set_keys({}))
        ngx.say("snapshot API passed")
    }
}
--- response_body
snapshot API passed


=== TEST 2: only bind tickets during ClientHello
--- config
location /t {
    content_by_lua_block {
        local tickets = require("resty.apisix.ssl_session_ticket")
        local ok, err = tickets.on_client_hello()
        assert(not ok)
        ngx.say(err)
    }
}
--- response_body
on_client_hello must run in ssl_client_hello_by_lua
