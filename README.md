# Authentication Cloudflare Worker

A Rust implementation of Cloudflare's authentication [integration guide for
Auth0][Integration Guide]. This worker uses Cloudflare's [Rust bindings](
https://github.com/cloudflare/workers-rs) and compiles targets a WASM binary.
This project was mainly an experiment to evaluate the platform and specifically
the Rust bindings. The goal here is _not to develop a production-ready
solution_, however it could be a useful starting place if you are following the
guide yourself.

Some things that could be implemented (among others) to further expand on this are:

  * Logout
  * PAT / Bearer token style authentication
  * Invitation-only sign up

## Trying it out

In order to try this yourself, you'll have to setup a Cloudflare account and
setup workers. You'll also need [Wrangler][], a CLI for managing Cloudflare
workers.

The [wrangler.toml](wrangler.toml) configuration should be updated with real
values from your own configuration if you want to try this out for yourself. In
addition, there are several secrets that you can setup for your worker through
wrangler.

```bash
# The domain of your AUTH0 application.
wrangler secret put AUTH0_DOMAIN
# The client secret for your application.
wrangler secret put AUTH0_CLIENT_SECRET
# The client ID for your application.
wrangler secret put AUTH0_CLIENT_ID
# Can be anything, is used for salting state tokens on login. You can generate
# one with `openssl rand -base64 12`.
wrangler secret put AUTH_SALT
```

```toml
name = "<INSERT DESIRED CLOUDFLARE WORKER NAME>"
type = "javascript"
workers_dev = true
compatibility_date = "2021-08-27"
compatibility_flags = [ "formdata_parser_supports_files" ]

kv_namespaces = [
  { binding = "AUTH_STORE", id = "<KV_BINDING>", preview_id = "<KV_BINDING>"}
]

[vars]
HOST_DOMAIN = "http://127.0.0.1:8787"
COOKIE_DOMAIN = "127.0.0.1"

[env.production]
kv_namespaces = [
  { binding = "AUTH_STORE", id = "<KV_BINDING>"}
]

[env.production.vars]
HOST_DOMAIN = "myaccounts.mydomain.com"
COOKIE_DOMAIN = "mydomain.com"

[build]
command = "cargo install -q worker-build && worker-build --release" # required

[build.upload]
dir    = "build/worker"
format = "modules"
main   = "./shim.mjs"

[[build.upload.rules]]
globs = ["**/*.wasm"]
type  = "CompiledWasm"
```

```sh
wrangler dev
```

<!-- FOOTER LINKS -->
[Integration Guide]: https://developers.cloudflare.com/workers/tutorials/authorize-users-with-auth0
[Wrangler]: https://developers.cloudflare.com/workers/cli-wrangler/install-update
