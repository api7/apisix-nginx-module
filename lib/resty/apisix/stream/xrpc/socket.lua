require("table.clone")
local base = require("resty.core.base")


base.allows_subsystem("stream")


local Downstream = {}
local Upstream = {}
local downstream_mt
local upstream_mt

-- need to remove methods which will break the buffer management
local function remove_unwanted_method(sk)
    local methods = getmetatable(sk).__index
    local copy = table.clone(methods)
    copy.receive = nil
    copy.receiveany = nil
    copy.receiveuntil = nil

    return {__index = copy}
end


local function set_method_table(sk, is_downstream)
    if is_downstream then
        if not downstream_mt then
            downstream_mt = remove_unwanted_method(sk)
        end
        return setmetatable(sk, downstream_mt)
    end

    if not upstream_mt then
        upstream_mt = remove_unwanted_method(sk)
    end
    return setmetatable(sk, upstream_mt)
end


function Downstream.socket()
    return set_method_table(ngx.req.socket(true), true)
end


function Upstream.socket()
    return set_method_table(ngx.socket.tcp(), false)
end


return {
    downstream = Downstream,
    upstream = Upstream,
}
