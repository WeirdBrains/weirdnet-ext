# Security

Report problems privately to m3talsmith@gmail.com.

## What the extension host protects

An extension is code from a third party running on the user's machine. The host aims to
make sure it can only do what the user granted:

- **Integrity**: a package is signed by its author's user key over the exact manifest bytes,
  and the manifest pins every file's BLAKE3 hash. An id is pinned to its first author for
  good; an update by another key is refused, and an update must be newer. Installed files
  are read-only and hashed again before every launch.
- **Isolation (Linux)**: the process has no environment beyond its own variables, inherits
  only its socket, runs with `no_new_privs`, and Landlock limits files to its package, the
  system libraries and its data directory, and denies TCP. The seccomp filter denies
  `socket()` outright (so no Unix socket paths such as D-Bus or the X server either),
  namespaces, mounts, `ptrace`, `process_vm_*`, `bpf`, `perf_event_open`, `io_uring`,
  `userfaultfd`, keyrings, kernel modules, `TIOCSTI`/`TIOCLINUX`, and the x32 ABI; `clone3`
  returns ENOSYS so `clone` flags stay visible to the filter.
- **Isolation (macOS)**: a deny-by-default `sandbox-exec` profile with the same file layout
  and no network.
- **Broker**: the one-time token is compared in constant time and spent on use; every later
  call needs the session id; calls are checked against the grants at call time.

## Known limits

- Below Linux 6.12 (Landlock ABI 6) the extension can send signals to the user's other
  processes; the [`Report`] notes it.
- `/proc` is not hidden beyond what Landlock blocks (the extension can't read other files
  there, but `/proc/self` metadata is visible). A private `/proc` would need bubblewrap,
  which can't run after Landlock; see the README.
- CPU and memory are limited with rlimits, not cgroups.
- `sandbox-exec` is deprecated by Apple; it still works on current macOS.
- Windows has no native sandbox yet; only WASM extensions are meant to run there.
