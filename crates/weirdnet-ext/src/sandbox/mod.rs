//! The process sandbox for native extensions.
//!
//! An extension process starts with an empty environment, its own process group, resource
//! limits, and a parent-death signal, and talks to the host only over the private socket the
//! host hands it. On top of that:
//!
//! - **Linux**: `no_new_privs`, a Landlock ruleset (files: only the paths in the [`Policy`];
//!   TCP bind and connect denied from ABI 4; abstract Unix sockets and signals outside the
//!   sandbox denied from ABI 6) and a seccomp filter that denies `socket()` (the extension
//!   already has its socket, so it can open no other), namespace and mount calls, `ptrace`,
//!   `bpf`, `io_uring`, kernel module and keyring calls, and terminal input injection.
//! - **macOS**: a `sandbox-exec` profile denying by default, allowing reads of the system
//!   libraries and the policy's paths, writes to the policy's write paths, and no network.
//! - **Windows**: native extensions don't run yet (see the README); use WASM.
//!
//! [`probe`] says what this machine gives; [`Policy::require`] refuses to start an
//! extension when a layer is missing instead of running it with less.

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;

use std::path::PathBuf;

/// Resource limits for an extension process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Address space in bytes (`RLIMIT_AS`); `None` for no limit.
    pub memory: Option<u64>,
    /// CPU seconds (`RLIMIT_CPU`).
    pub cpu_secs: Option<u64>,
    /// Open files (`RLIMIT_NOFILE`).
    pub open_files: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self { memory: Some(4 << 30), cpu_secs: None, open_files: Some(256) }
    }
}

/// How strict a launch must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Require {
    /// Every layer this OS has must be in force (Landlock with network rules and seccomp on
    /// Linux; the profile on macOS). The default.
    #[default]
    Full,
    /// Run with whatever this machine gives (older kernels), and say so in the [`Report`].
    BestEffort,
}

/// What an extension process may touch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Paths it may read (files or directories, recursively).
    pub read: Vec<PathBuf>,
    /// Paths it may read and execute (its own binary, the system libraries).
    pub read_exec: Vec<PathBuf>,
    /// Paths it may read and write (its data directory).
    pub write: Vec<PathBuf>,
    /// Resource limits.
    pub limits: Limits,
    /// How strict to be.
    pub require: Require,
}

impl Policy {
    /// The policy for an installed extension: read and execute its own directory and the
    /// system libraries, read the few system files a dynamically linked program needs, read
    /// and write `data`.
    pub fn for_extension(ext_dir: impl Into<PathBuf>, data: impl Into<PathBuf>) -> Self {
        let mut read_exec: Vec<PathBuf> = vec![ext_dir.into()];
        let mut read = Vec::new();
        #[cfg(target_os = "linux")]
        {
            for p in ["/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/libexec", "/nix/store"] {
                read_exec.push(p.into());
            }
            for p in [
                "/etc/ld.so.cache",
                "/etc/ld.so.preload",
                "/etc/localtime",
                "/usr/share/zoneinfo",
                "/dev/null",
                "/dev/urandom",
                "/dev/random",
                "/sys/devices/system/cpu",
                "/sys/fs/cgroup",
            ] {
                read.push(p.into());
            }
        }
        #[cfg(target_os = "macos")]
        {
            for p in ["/usr/lib", "/System/Library", "/System/Volumes/Preboot/Cryptexes", "/System/Cryptexes", "/Library/Apple/usr/lib"] {
                read_exec.push(p.into());
            }
            for p in ["/dev/null", "/dev/urandom", "/dev/random", "/private/var/db/timezone", "/usr/share/zoneinfo"] {
                read.push(p.into());
            }
        }
        Self { read, read_exec, write: vec![data.into()], limits: Limits::default(), require: Require::Full }
    }
}

/// What the sandbox did (or could do) on this machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The OS mechanism: "landlock+seccomp", "sandbox-exec", or "none".
    pub mechanism: &'static str,
    /// The Landlock ABI version, if any (Linux).
    pub landlock_abi: Option<u32>,
    /// Whether file access is limited to the policy.
    pub files: bool,
    /// Whether the extension can't open network connections of its own.
    pub network: bool,
    /// Whether the syscall filter is in force (Linux).
    pub syscalls: bool,
    /// What is missing that [`Require::Full`] needs, in words.
    pub missing: Vec<String>,
    /// Weaker spots that don't stop a launch, in words (such as signal scoping on kernels
    /// before 6.12).
    pub notes: Vec<String>,
}

impl Report {
    /// True if nothing is missing.
    pub fn full(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Whether native extensions can run on this OS at all.
pub fn native_allowed() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

/// What the sandbox can do on this machine.
pub fn probe() -> Report {
    #[cfg(target_os = "linux")]
    {
        linux::probe()
    }
    #[cfg(target_os = "macos")]
    {
        macos::probe()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Report { mechanism: "none", missing: vec!["native extensions are not supported on this OS".into()], ..Default::default() }
    }
}

/// Builds the command for a native extension: sandboxed, empty environment except `env`,
/// own process group, killed when dropped. `keep_fd` is the only descriptor it inherits.
#[cfg(unix)]
pub(crate) fn command(
    binary: &std::path::Path,
    args: &[String],
    policy: &Policy,
    keep_fd: std::os::fd::RawFd,
    env: &[(String, String)],
) -> crate::error::Result<(tokio::process::Command, Report)> {
    #[cfg(target_os = "linux")]
    let (prep, report, mut cmd) = {
        let (p, r) = linux::prepare(policy, keep_fd)?;
        (p, r, tokio::process::Command::new(binary))
    };
    #[cfg(target_os = "macos")]
    let (prep, report, mut cmd) = {
        let (p, r) = macos::prepare(policy, keep_fd)?;
        let mut c = tokio::process::Command::new(macos::SANDBOX_EXEC);
        c.arg("-p").arg(&p.profile).arg(binary);
        (p, r, c)
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (binary, args, policy, keep_fd, env);
        return Err(crate::error::Error::Unsupported("native extensions don't run on this OS".into()));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        cmd.args(args).env_clear().envs(env.iter().map(|(k, v)| (k, v))).kill_on_drop(true).process_group(0);
        cmd.stdin(std::process::Stdio::null());
        if let Some(dir) = policy.write.first() {
            cmd.current_dir(dir);
        }
        // SAFETY: `apply` makes only async-signal-safe calls on memory prepared before the fork.
        unsafe {
            cmd.pre_exec(move || prep.apply());
        }
        Ok((cmd, report))
    }
}
