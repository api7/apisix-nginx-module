# APISIX Nginx Module

## Directive

### apisix_delay_client_max_body_check [on|off]

default: off

Delay client_max_body_size check until the body is read.

### apisix_mirror_on_demand [on|off]

default: off

Disable request mirror until we enable it in the Lua code.

### apisix_stream_metrics_zone \<size\>

context: `stream`

default: off

Reserve a shared memory zone that collects, per stream listening address, the
number of active sessions and the bytes transferred in the four directions
(downstream/upstream × ingress/egress). Counters are merged into the zone at
most once per second per session and flushed when the session ends, so they
keep moving during long-lived connections without paying an atomic operation
per read or write. Without this directive nothing is collected.

example:

```nginx
stream {
    apisix_stream_metrics_zone 1m;
}
```

Read the counters from Lua with `resty.apisix.stream.metrics`:

```lua
local metrics = require("resty.apisix.stream.metrics")
local res, err = metrics.dump()
-- res[i] = { listen_addr = "0.0.0.0:9100", active = 3,
--            downstream_ingress = 12, downstream_egress = 34,
--            upstream_egress = 12, upstream_ingress = 34 }
```

## Variable

### $stream_session_reason

context: `stream`

Why the session ended. nginx keeps `$status` at 200 for every failure that
happens after the upstream connection is established, so this variable is what
tells a graceful close apart from a timeout or a reset:

| value | meaning |
|---|---|
| `closed` | one side sent a FIN, the session ended normally |
| `client_rst` | the client reset the connection |
| `client_error` | sending to the client failed |
| `upstream_rst` | the upstream reset the connection |
| `upstream_error` | sending to the upstream failed |
| `connect_timeout` | connecting to the upstream timed out and no peer was left |
| `recv_timeout` | `proxy_timeout` expired while waiting for data |
| `send_timeout` | `proxy_timeout` expired with data still buffered towards a peer |
| `upstream_timeout` | a UDP upstream never answered |
| `shutdown` | the worker was shutting down |
| `-` | not applicable, for example a session rejected before `proxy_pass` |

Available whether or not `apisix_stream_metrics_zone` is configured.

### $stream_listen_addr

context: `stream`

The configured listening address the session came in on, for example
`0.0.0.0:9100`. This is the key the metrics zone uses for its slots; unlike
`$server_addr`, which holds the address the connection was accepted on, it
stays the same on a wildcard listen.

## Block

### lua

Apply ngx.shared.DICT that shared by http and stream subsystem.

example:

```nginx
lua {
    lua_shared_dict prometheus-metrics 15m;
}
```
