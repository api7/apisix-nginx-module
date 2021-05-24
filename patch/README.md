## Where does the patches come?

The `*-tlshandshake` patches originally come from the tlshandshake pull request to OpenResty.
We have modified them a lot and even changed the API.

The `*-upstream_mtls` patches originally come from the Kong's kong-build-tools and lua-kong-nginx-module
projects, which is also under Apache-2.0 License.

The `*-ngx_pipe_environ_on_mac` patches support the environ argument of the ngx.pipe.spawn function on macos.