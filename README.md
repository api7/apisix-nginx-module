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

Reserve a shared memory zone that collects, per stream listening address (and
per set of labels, see below), the number of active sessions and the bytes
transferred in the four directions (downstream/upstream × ingress/egress). A
session accumulates locally and merges into the zone once per forwarding pass,
so the counters keep moving during a long-lived connection while the inner
read/write loop still costs a single atomic per direction. Without this
directive nothing is collected.

example:

```nginx
stream {
    apisix_stream_metrics_zone 1m;
}
```

Only TCP and UDP listening addresses are accounted for. **Every** unix socket
inside `stream{}` is skipped, including one you configured yourself to proxy
on: the filter is on the address family, not on which server owns it. This is
what keeps APISIX's own worker event channel, which lives on a unix socket in
the same block, from being reported as proxied traffic.

Things worth knowing before building alerts on this:

- The byte counters are monotonic from the moment the zone is created. They
  restart at zero when the process restarts, when the configured zone size
  changes (nginx only reuses a zone whose size is unchanged), and when a
  reload removes the directive or the whole `stream{}` block, since the zone
  is then released.
- Slots are only ever added. A listening address removed by a reload keeps its
  slot, and its accumulated totals, until the process restarts.
- A counter is written once per forwarding pass and again when the session
  ends, so a session that has gone quiet has already published everything it
  moved.
- A TCP and a UDP listener on the same port share one slot: nginx gives them
  the same address text, so their traffic is summed and `$stream_listen_addr`
  cannot tell them apart.
- `active` is decremented in the log phase, which nginx runs for every session
  it finalizes, including on a graceful shutdown. A worker that dies without
  running it (a crash, or `SIGKILL`) leaks its in-flight sessions into the
  count, and nothing rebases the zone until the process restarts.
- With `proxy_next_upstream`, the upstream byte counters sum every attempt,
  including what was sent to a peer that then failed. `$upstream_bytes_sent`
  and `$upstream_bytes_received` instead report one value per attempt, comma
  separated, so comparing them against these counters means summing them
  first. For a session that reached its upstream on the first try the two
  agree directly.

Read the counters from Lua with `resty.apisix.stream.metrics`:

```lua
local metrics = require("resty.apisix.stream.metrics")
local res, err = metrics.dump()
-- res[i] = { listen_addr = "0.0.0.0:9100", labels = {}, active = 3,
--            downstream_ingress = 12, downstream_egress = 34,
--            upstream_egress = 12, upstream_ingress = 34 }
```

A session can be split out of its listening address by labelling it, typically
from `preread_by_lua*` once it is known what the session belongs to. The
labels are label values, in the order the caller's own metric declares its
labels; the names stay with the caller:

```lua
local ok, err = metrics.set_labels({ "svc-a", "order" })
```

From then on its active count and the bytes it moves are accounted on the slot
of its listening address and labels, which `dump()` reports as a separate entry
with those values in `labels`. Bytes stay on the entry they were counted on:
what a session moved before it was first labelled, and every session that is
never labelled, stays on the unlabelled entry (`labels = {}`), and what it
moved under one set of labels stays there if it is labelled again later. The
entries of one listening address therefore always add up to its total. An
empty array moves the session back to the unlabelled entry.

- The values are joined into one byte string of at most 512 bytes, `\31`
  between them, so a value cannot contain `\31`. An array holding just `""`
  joins to the same empty string as `{}` and is the unlabelled entry too.
- A slot is claimed the first time a worker sees a set of labels on a listening
  address and, like any slot, is kept until the process restarts, so label
  values must come from a bounded set.
- A slot takes about 690 bytes and only half of the zone is handed out, so a
  zone holds about `size / 2 / 690` slots: about 760 for `1m`. A quarter of
  them is kept for listening addresses, which labels cannot take, so that an
  address added by a later reload is still counted when labels have filled
  the rest.
- When no slot is left for labels, `set_labels` returns
  `nil, "stream metrics zone is full"` and the session stays on the slot it
  already had. Each worker logs this once, at `warn`.
- Each worker caches the slots of the last 256 or so sets of labels it used.
  More sets than that in active use still work, but a session may then have
  to look its slot up across the whole zone.
- Without a zone, or on a listening address that is not accounted for,
  `set_labels` returns `nil, "not accounted"`.

## Variable

### $stream_session_reason

context: `stream`

Why the session ended. nginx keeps `$status` at 200 for every failure that
happens after the upstream connection is established, so this variable is what
tells a graceful close apart from a timeout or a reset:

| value | meaning |
|---|---|
| `closed` | one side sent a FIN, the session ended normally |
| `client_rst` | the client reset the connection (`ECONNRESET`) |
| `client_read_error` | reading from the client failed for any other reason, including a TLS protocol failure |
| `client_error` | sending to the client failed |
| `upstream_rst` | the upstream reset the connection (`ECONNRESET`) |
| `upstream_read_error` | reading from the upstream failed for any other reason |
| `upstream_error` | sending to the upstream failed |
| `connect_timeout` | connecting to the upstream timed out and no peer was left |
| `recv_timeout` | `proxy_timeout` expired while waiting for data |
| `send_timeout` | `proxy_timeout` expired with data still buffered towards a peer |
| `upstream_timeout` | a UDP upstream never answered |
| `shutdown` | the worker was shutting down |
| `connect_failed` | no upstream could be reached: refused, no live node, or a failed upstream handshake |
| `-` | no reason applies, for example a session rejected during preread |

A UDP session has no close to observe, so one that ends normally -- including
one that ends on `proxy_timeout` with the expected responses received --
reports `closed`. `closed` therefore does not distinguish the two for UDP.

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
