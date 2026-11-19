# Dynamic HTTP TLS session ticket keys

This data-plane API replaces a worker's ticket keys without reloading NGINX.
It extends NGINX's existing ticket callback: native AES/HMAC processing, ticket
format, session cache, and TLS 1.3 renewal remain in NGINX. It does not install
another OpenSSL ticket callback or depend on `lua-ssl-nginx-module`.

The patch and module belong together. Apply `patch/patch.sh` before building
OpenResty with this module statically. Native hook patches are provided for the
`1.27.1.1`, `1.29.2.4`, and `1.31.1.1` patch families, with OpenSSL early-data
APIs available. Older patch families and builds without that native hook
remain unchanged; `is_supported()` returns `false` there.

## Configuration and integration

```nginx
http {
    lua_package_path "/path/to/apisix-nginx-module/lib/?.lua;;";

    ssl_session_cache shared:SSL:20m;
    ssl_session_timeout 10m;
    ssl_session_tickets on;
    ssl_early_data off;

    server {
        listen 443 ssl;
        ssl_certificate server.crt;
        ssl_certificate_key server.key;

        ssl_client_hello_by_lua_block {
            local tickets = require("resty.apisix.ssl_session_ticket")
            local ok, err = tickets.on_client_hello()
            if not ok then
                ngx.log(ngx.ERR, err)
                return ngx.exit(ngx.ERROR)
            end
        }
    }
}
```

Do **not** configure `ssl_session_ticket_key`, including a placeholder file.
The shared cache makes NGINX register its native callback and automatic key
slots even without a key file. Binding checks the shared cache, tickets-on,
absence of explicit key files, and early-data-off prerequisites. Treat a
binding error as a failed handshake, not a reason to silently use local keys.

Call `on_client_hello()` on every managed HTTP handshake, before existing
application ClientHello processing. In APISIX, retain the subsequent
`apisix.ssl_client_hello_phase()` call. Do not add this hook to Admin HTTPS or
stream TLS. A context that never calls this API retains native NGINX behavior.
All connections of a managed context must execute the hook; do not opt in
conditionally based on SNI on a context shared with unmanaged connections.

## `set_keys(keys)`

Call this in **each worker** after the caller has obtained and decrypted its
current local key set. There is no etcd client, watch, encryption-at-rest,
resource revision tracking, or inter-worker distribution in this module.
New workers start with an empty key set, including after a graceful reload;
the caller must replay its local view to each new worker. Until then, managed
handshakes use the local-cache fallback.

```lua
local tickets = require("resty.apisix.ssl_session_ticket")
assert(tickets.is_supported())

local function apply_keys(current_local_view)
    local keys = {}
    for position, resource in ipairs(current_local_view) do
        keys[position] = {
            key = resource.raw_key,
            encrypt_from = resource.encrypt_from,
            encrypt_until = resource.encrypt_until,
            decrypt_until = resource.decrypt_until,
            lifetime = resource.lifetime,
        }
    end
    return tickets.set_keys(keys)
end
```

`keys` is a dense array of at most 256 records. Each record contains:

| Field | Meaning |
| --- | --- |
| `key` | Exactly 80 raw bytes: `name[16]` + `HMAC[32]` + `AES[32]`, matching NGINX's 80-byte key-file layout. Not base64. |
| `encrypt_from` | Inclusive Unix signing start, in seconds. |
| `encrypt_until` | Exclusive Unix signing end, in seconds. |
| `decrypt_until` | Exclusive Unix decryption end, in seconds. |
| `lifetime` | Session timeout/ticket lifetime hint, integer seconds in `1..604800`. |

Timestamps must be nonnegative exact Lua integers at most `2^53 - 1` and
satisfy `encrypt_from < encrypt_until < decrypt_until`. Key names must be
unique. The caller must validate resource identity against the first 16 bytes
and isolate invalid resources before constructing the local view if its
resource contract requires partial application.

On success, returns `true`. The C implementation copies the complete set into
worker-owned storage without yielding, and wipes the replaced storage. The
Lua FFI staging buffer is also wiped. It retains no caller-owned strings, but
Lua strings held by the caller or temporary decoding buffers cannot be
guaranteed to be physically erased.

On invalid input, returns `nil, err` and leaves the prior set intact. This
atomic low-level API does not decide application-level revocation policy.
When an authoritative update removes a key, the caller must submit the new
complete local view, excluding that key. `set_keys({})` clears all managed
keys immediately in that worker. An application that cannot safely construct
a replacement should explicitly clear the set rather than acknowledge a
revocation it did not apply. The module does not log or expose key bytes.

All opted-in HTTP contexts in a worker share this single key set. Separate
tenant-specific key rings are not supported by this API.

## Time windows and fallback

- A signing key satisfies `encrypt_from <= now < encrypt_until`. Among
  overlaps, greatest `encrypt_from` wins; ties use the greatest 16-byte name
  in unsigned byte order, equivalent to greatest lowercase hex identifier.
- Every loaded key with `now < decrypt_until` can decrypt, including a
  preloaded future signing key, **provided some current signing key exists**.
- With no current signing key, the ClientHello hook sets `SSL_OP_NO_TICKET`
  on both the context and current connection. NGINX/OpenSSL use the existing
  local shared session cache instead; cross-node stateless resumption is not
  available. TLS 1.3 may issue stateful, local-cache tickets in this mode.
- When a signing key becomes valid again, the next ClientHello clears both
  options and restores stateless tickets automatically. No reload is needed.
- The native ticket callback checks wall-clock windows again at actual
  encryption/decryption time. A timer delay or a handshake paused by Lua
  cannot extend those windows. If the signing window ends after ClientHello,
  that handshake may complete without a new ticket rather than encrypting
  with an expired key.
- ClientHello applies the current signer's `lifetime` with
  `SSL_CTX_set_timeout`. Fallback keeps the last applied timeout (initially
  the configured `ssl_session_timeout`). Restored sessions retain native
  OpenSSL session-age/lifetime checks; there is no separate absolute
  handshake-age policy.
- Removing or expiring a key affects new resumptions, not established TLS
  connections. Disconnected workers still enforce their loaded deadlines
  but cannot learn a new revocation without a caller update.

No network or file I/O runs in the ClientHello helper or native ticket
callback. Key selection scans at most 256 worker-local records. Native
unmanaged HTTP, Admin, and stream callbacks still use their existing keys.
Existing SNI isolation and client-certificate resumption checks remain the
application's responsibility and must not be bypassed by the integration.
0-RTT is deliberately unsupported.

## Other APIs

`is_supported()` returns whether this binary includes the native hook.

`on_client_hello()` returns `true` or `nil, err`, and is allowed only in
`ssl_client_hello_by_lua*`. It binds the HTTP context and applies its current
options and timeout before OpenSSL's resumption decision.

`expire_keys()` wipes expired native key bytes in the current worker and
returns `true` or `nil, err`. Handshakes also perform this cleanup, so a timer
is not required for correctness. To release expired secrets during idle
periods, a caller can invoke it from an existing worker timer. Context
options and timeout are refreshed by the next ClientHello, not by this API.
Worker exit wipes the native key table as well.

## Verification

```sh
prove -I. -Itest-nginx/lib t/ssl-session-ticket.t
TEST_NGINX_BINARY=/path/to/nginx python3 t/ssl-session-ticket.py
```

The Python suite starts disposable local nodes, generates test-only keys and
certificates, and exercises real TLS 1.2/1.3 resumptions without external
services. The Test::Nginx suite validates API input and the unsupported-build
contract. Run APISIX-level SNI and mTLS regression tests as well before
enabling this in a gateway; this repository does not implement that wiring.
