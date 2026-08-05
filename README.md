# APISIX Nginx Module

## Directive

### apisix_delay_client_max_body_check [on|off]

default: off

Delay client_max_body_size check until the body is read.

### apisix_mirror_on_demand [on|off]

default: off

Disable request mirror until we enable it in the Lua code.

### apisix_var_index $name ...

Mark the given NGINX variables as indexed, so that `resty.apisix.var` can read
and write them by index. Only valid in the `http` block.

Variables that the configuration already references (through `set`, a log
format, `proxy_pass`, ...) are indexed by NGINX itself and need no directive.

```nginx
apisix_var_index $request_uri $upstream_status;
```

> **Caution**: NGINX caches the value of an indexed variable in
> `r->variables[]`, and a variable that is only read through `ngx.var` is
> otherwise resolved on every access. Indexing a header variable such as
> `$http_user_agent` therefore makes a later `ngx.req.set_header()` invisible to
> readers of that variable. Do not index `$http_*`, `$arg_*`, `$cookie_*`,
> `$sent_http_*`, `$upstream_http_*` or `$upstream_cookie_*` unless the request
> never rewrites them.

## Library

### resty.apisix.var

Index based access to the NGINX variables, skipping the name normalization,
the hash lookup and the per-access `r->pool` allocation that `ngx.var` performs
on every read.

`load_indexes()` builds the name to index map from `cmcf->variables`. It has to
run in the `init_worker` phase or later: before `ngx_init_cycle()` commits, the
`ngx_cycle` global still points at the previous cycle.

```nginx
init_worker_by_lua_block {
    require("resty.apisix.var").load_indexes()
}
```

```lua
local var = require("resty.apisix.var")

-- get/set fall back to ngx.var when the variable is not indexed
local uri = var.get("request_uri")
local ok, err = var.set("my_var", "value")

-- or address the variable by its index directly
local index = var.indexes["request_uri"]
local uri = var.get_by_index(index)
```

Reading an indexed variable by index is semantically identical to reading it by
name: `ngx_http_get_variable()` already dispatches to
`ngx_http_get_indexed_variable()` for those variables.

Writing follows `ngx.var`: a variable with a `set_handler` goes through it, an
indexed one is written into `r->variables[]`, and anything else (including a
prefix variable such as `$http_foo`, which has no entry of its own in
`cmcf->variables_hash`) is rejected.

## Block

### lua

Apply ngx.shared.DICT that shared by http and stream subsystem.

example:

```nginx
lua {
    lua_shared_dict prometheus-metrics 15m;
}
```
