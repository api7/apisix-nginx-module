-- This module stores the flags which mark the difference between
-- APISIX's OpenResty and vanilla OpenResty.
-- We use flag to distinguish the difference when it is impossible
-- to distinguish APISIX's OpenResty via additional module methods.
local _M = {
    client_cert_verified_in_handshake = true
}


return _M
