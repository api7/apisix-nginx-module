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

The `*-shared_shdict` patches, `src/meta/*` and `t/meta/*` originally come from:
https://github.com/openresty/meta-lua-nginx-module/pull/76
https://github.com/thibaultcha/lua-resty-core/commit/8ad30813a3d8037f92aaaffaacd0a14bc7388edf
, which is under BSD license.
