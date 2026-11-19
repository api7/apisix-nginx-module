# APISIX Nginx Module

## Directive

### apisix_delay_client_max_body_check [on|off]

default: off

Delay client_max_body_size check until the body is read.

### apisix_mirror_on_demand [on|off]

default: off

Disable request mirror until we enable it in the Lua code.

### apisix_ssl_session_ticket_takeover [on|off]

context: `server` (http and stream)

default: off

Hand the TLS session ticket keys of this server's SSL context over to Lua:
instead of the keys nginx rotates in `ssl_session_cache` or reads from
`ssl_session_ticket_key`, the context encrypts and decrypts tickets with a
complete, ordered set of keys installed through
[`resty.apisix.ssl_session_ticket`](#restyapisixssl_session_ticket). Servers
of different nodes that install the same set resume each other's sessions.

```nginx
server {
    listen 9443 ssl;
    ssl_certificate     cert.pem;
    ssl_certificate_key cert.key;
    ssl_session_tickets off;
    apisix_ssl_session_ticket_takeover on;
}
```

- The directive is only allowed in `server{}`, so a mark is never inherited
  from `http{}` or `stream{}`: every server, including each of several stream
  servers, is marked on its own. A server that is not marked, such as the
  Admin API, keeps the native behavior, including the keys nginx rotates in a
  session cache it shares with a marked server.
- A marked context starts with stateless tickets off whatever
  `ssl_session_tickets` says, and stays off until Lua installs a set and turns
  them on. Without a set it never falls back to keys of its own.
- It works without a session cache, the stream default.
- It cannot be combined with `ssl_session_ticket_key`, nginx refuses to start.
- Only a server that has an SSL context is concerned: one with
  `ssl_certificate` or `ssl_reject_handshake on`. When several servers share a
  listening address, tickets follow the context the handshake starts with,
  the one of the default server of that address, as for native nginx.
- The takeover needs the `nginx-ssl_session_ticket_takeover` patch, which only
  exists for OpenResty 1.31.1.1 (nginx 1.31.1), the release it is verified
  against: the module refuses to compile with the patch on any other nginx.
  Other builds accept the directive with a warning and take nothing over, and
  the Lua API reports `not_supported`.

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
  already had.
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

## Lua API

### resty.apisix.ssl_session_ticket

Manages the servers marked with
[`apisix_ssl_session_ticket_takeover`](#apisix_ssl_session_ticket_takeover-onoff).
The module works in the http and in the stream subsystem, and only ever sees
the marked servers of the subsystem it runs in, as the current worker has
them. Every function returns `nil` and an error on failure; see the table
below.

```lua
local ticket = require("resty.apisix.ssl_session_ticket")

-- turn tickets on: a complete set first, then the switch
assert(ticket.set_keys(id, { current, previous }))
assert(ticket.enable_tickets(id))

-- and off: the switch first, then the keys
assert(ticket.disable_tickets(id))
assert(ticket.revoke_keys(id))
```

- `contexts()` returns the marked servers:
  `{ id = 1, registered = true, tickets = false, keys = 0, generation = 1,
  conf = "/path/nginx.conf:42" }`. `id` is the position of the server in the
  configuration, starting at 1, and does not change for the life of the
  worker. `registered` tells that the ticket callback was registered for this
  context in the configuration generation of the worker; OpenSSL has no getter
  for the callback, so this is the record the successful registration left on
  the context. A context with `registered = false` stays off: it takes no keys
  and its tickets cannot be turned on. `tickets` is true when
  `SSL_OP_NO_TICKET` is clear on the context, `keys` counts the installed keys
  and `conf` tells where the directive is, for diagnostics only. Use it from
  `init_worker_by_lua*` on: in `init_by_lua*` the configuration being loaded
  is not committed yet, and its contexts do not verify.
- `set_keys(id, keys)` installs a complete, ordered set of keys: the first one
  encrypts new tickets, every one decrypts. A key is 80 raw bytes in the nginx
  layout, `name(16) | HMAC-SHA256(32) | AES-256-CBC(32)`; names must be unique
  and there are 1 to `MAX_KEYS` (256) of them. The set replaces the previous
  one as a whole, which is never visible half replaced; a rejected set leaves
  the previous one in place. It does not change whether tickets are on. As
  nginx does, a ticket decrypted with any key but the first is renewed under
  the first one, and every TLSv1.3 resumption gets a new ticket.
- `enable_tickets(id)` clears `SSL_OP_NO_TICKET` on the context. It needs a
  verified registration and an installed set.
- `disable_tickets(id)` sets `SSL_OP_NO_TICKET` on the context and keeps the
  set.
- `revoke_keys(id)` sets `SSL_OP_NO_TICKET`, then wipes and drops the set.
- `sync_connection()` aligns `SSL_OP_NO_TICKET` on the TLS connection of the
  current request with its context, and returns whether the connection may
  use stateless tickets, and the id of its context. A connection copies the
  options of the context when it is accepted, so a context switched while the
  handshake is pending does not reach it otherwise: call it from
  `ssl_client_hello_by_lua*`, after bringing the context up to date.
- `connection_tickets()` returns the same as `sync_connection()` without
  changing the connection.

Turning tickets off only stops stateless tickets: TLSv1.2 then issues none,
while TLSv1.3 keeps sending the stateful tickets of the session cache, and
whether those resume depends on the cache, as before. None of the calls closes
a connection. Whatever the options of a connection say, the context refuses to
encrypt or decrypt a ticket once it is off or has no keys: a refused ticket
means a full handshake, and a refused encryption an empty ticket in TLSv1.2 and
no ticket in TLSv1.3, never a handshake failure.

| error | meaning |
|---|---|
| `not_supported` | this nginx cannot take over the keys, see the directive |
| `not_registered` | the server is marked, but the callback registration failed or does not verify; the context stays off |
| `no_context` | the current subsystem and worker have no marked server with this id |
| `invalid_keys` | the set is rejected (empty, a key not 80 bytes, too many keys, a duplicate name), followed by `: ` and a reason |
| `no_keys` | tickets cannot be turned on without a set |
| `failed` | out of memory, the previous set stays |
| `not_marked` | the context of the current connection is not marked |
| `no_request`, `no_ssl` | the connection functions need the request of a TLS connection |

### resty.apisix.process

- `get_generation()` returns the configuration generation of the process: 1
  for the configuration the master started with, then one more for each
  successful reload. A worker keeps the generation it was started for, so the
  workers of two generations that overlap during a reload tell apart, which
  `ngx.worker.id()` does not; a worker the master restarts after a crash gets
  the generation of its siblings. It is 0 until the first configuration is in
  place, in `init_by_lua*` for instance, and starts over with nginx, as the
  shared memory zones do.
- `get_identity()` returns
  `{ type = "worker", pid = 1234, worker_id = 0, worker_count = 4,
  generation = 3, slot = 0 }`, where `type` is `ngx.process.type()`. `slot` is
  the worker id for a worker or a single process, `worker_count` for the
  privileged agent and `nil` for the other processes: within a generation it
  stays below `worker_count + 1`, and a restarted worker gets its slot back,
  with another pid.
