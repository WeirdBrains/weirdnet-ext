# weirdnet-ext

Extensions for Weirdnet apps: signed packages, capability grants, a per-OS sandbox, and a
gRPC contract between the app and each extension process.

| Crate | What |
| --- | --- |
| [`weirdnet-ext-proto`](crates/weirdnet-ext-proto) | `weirdnet.ext.v1`, the protobuf contract (tonic stubs) |
| [`weirdnet-ext`](crates/weirdnet-ext) | the host: packages, install/update rules, grants, sandbox, supervisor, broker |
| [`weirdnet-ext-sdk`](crates/weirdnet-ext-sdk) | for extension authors: connect, call, log, health, events |

`tests-e2e` builds a real extension, packages and installs it, and runs it in the sandbox:
it tries to read `/etc/passwd`, write outside its data directory, open TCP and Unix
sockets, `ptrace`, `unshare`, `io_uring` and signal init, and checks it inherits only its
socket and a clean environment. It also covers crash restarts with backoff, the stop grace
period, idle stops, grant revocation, and a tampered install.

## Platforms

| OS | Native extensions |
| --- | --- |
| Linux 5.13+ | Landlock + seccomp (network rules from 6.7 / ABI 4, signal and abstract-socket scoping from 6.12 / ABI 6) |
| macOS | `sandbox-exec` deny-by-default profile |
| Windows | not yet; the planned AppContainer launcher is future work, run the WASM build |

Not done yet: the WASM (WIT) bridge for extensions on platforms without native support, a
bubblewrap layer (Landlock forbids the mounts bubblewrap needs once applied, so the two
can't simply stack; Landlock + seccomp already cover what bwrap would add except a private
`/proc`), and Windows AppContainer.

## Development

```sh
cargo test --workspace
```

BSD-3-Clause. See [SECURITY.md](SECURITY.md) for the threat model.
