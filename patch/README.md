## Where does the patches come?

The `*-tlshandshake` patches originally come from the tlshandshake pull request to OpenResty.
We have modified them a lot and even changed the API.

The `*-upstream_mtls` patches originally come from the Kong's kong-build-tools and lua-kong-nginx-module
projects, which is also under Apache-2.0 License.

The `*-expose_request_struct.patch` patches originally come from the Kong's kong-build-tools
projects, which is also under Apache-2.0 License.

The `*-ngx_pipe_environ_on_mac` patches support the environ argument of the ngx.pipe.spawn function on macos.

The `*-enable_keepalive` patches originally come from:
https://github.com/openresty/lua-nginx-module/pull/1600
https://github.com/openresty/lua-resty-core/pull/276

The `*-ngx_meta_lua_module` patches, `src/meta/*` and `t/meta/*` originally come from:
https://github.com/openresty/meta-lua-nginx-module/pull/76, which is under BSD license.
Copyright and License of this PR:
This repository is licensed under the BSD license.

Copyright (C) 2009-2017, by Xiaozhe Wang (chaoslawful) chaoslawful@gmail.com.

Copyright (C) 2009-2019, by Yichun "agentzh" Zhang (章亦春) agentzh@gmail.com, OpenResty Inc.

All rights reserved.
