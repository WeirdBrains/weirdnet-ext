# weirdnet-ext

The Weirdnet extension host: what an app (such as Morph) needs to install and run
third-party extensions safely.

- **Packages** ([`package`]): a tar archive with `manifest.json`, `manifest.sig` and the
  files. The author's Weirdnet user key (Ed25519) signs the exact manifest bytes; the
  manifest lists every file with its size and BLAKE3 hash. Opening a package checks all of
  it and refuses unlisted files, links, unsafe paths and oversized archives.
- **Install and update rules** ([`Installer`]): one read-only directory per version; each
  extension id is pinned to its first author, so another key can't take it over (not even
  after an uninstall); an update must be newer; [`Plan::new_capabilities`] lists what an
  update adds so the app can ask the user; every launch hashes the files again.
- **Grants** ([`Grants`]): capabilities with optional `*` patterns, checked on every call; a
  revoked capability fails the next call.
- **Sandbox** ([`sandbox`]): empty environment, own process group, resource limits,
  parent-death signal, and only the private socket inherited. Linux adds `no_new_privs`,
  Landlock (files limited to the package, the system libraries and the data directory; TCP
  denied; abstract Unix sockets and signals scoped on 6.12+) and a seccomp filter (no
  `socket()`, namespaces, mounts, `ptrace`, `bpf`, `io_uring`, keyrings, modules or terminal
  injection). macOS uses a deny-by-default `sandbox-exec` profile. Windows: not yet (WASM
  only). [`sandbox::probe`] reports what a machine gives; the default
  [`Require::Full`] refuses to run with less.
- **Supervisor** ([`supervisor`]): starts the extension with a fresh socket pair and a
  one-time token, serves the [`broker`] (`weirdnet.ext.v1.Host` over gRPC), restarts crashes
  with backoff and gives up after repeated ones, stops idle extensions, and kills stuck ones
  after a grace period.

```rust,no_run
use std::sync::Arc;
use weirdnet_ext::{Config, Grants, Installer, NoServices, supervisor};

# async fn f(bytes: Vec<u8>) -> weirdnet_ext::Result<()> {
let installer = Installer::new("/home/me/.local/share/morph/extensions");
let plan = installer.inspect(&bytes)?;      // verify; show plan.new_capabilities to the user
let installed = installer.install(plan)?;
let grants = Grants(installed.manifest.capabilities.clone()); // what the user agreed to
let h = supervisor::start(Config::new("morph 0.5.0", installer, &installed.manifest.id,
    "/home/me/.local/share/morph/ext-data/reader", grants, Arc::new(NoServices)));
h.send("morph.ext.v1.PageLoaded", vec![]).await;
h.stop("quit").await;
# Ok(()) }
```

Extensions are written with [`weirdnet-ext-sdk`](https://crates.io/crates/weirdnet-ext-sdk);
the wire contract is [`weirdnet-ext-proto`](https://crates.io/crates/weirdnet-ext-proto).
BSD-3-Clause.
