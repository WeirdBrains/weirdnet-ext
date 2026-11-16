//! macOS: a `sandbox-exec` profile that denies by default.
//!
//! `sandbox-exec` is deprecated by Apple but still ships and still enforces; an App Sandbox
//! helper is the long-term replacement (see the README).

use super::{Policy, Report, Require};
use crate::error::{Error, Result};
use std::os::fd::RawFd;
use std::path::Path;

pub(crate) const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

pub(crate) fn probe() -> Report {
    let ok = Path::new(SANDBOX_EXEC).exists();
    Report {
        mechanism: "sandbox-exec",
        landlock_abi: None,
        files: ok,
        network: ok,
        syscalls: false,
        missing: if ok { vec![] } else { vec![format!("{SANDBOX_EXEC} is missing")] },
        notes: vec!["no syscall filter on macOS".into()],
    }
}

fn quote(p: &Path) -> String {
    let s = p.to_string_lossy();
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('"');
    o
}

fn canon(p: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// The SBPL profile for `policy`.
pub(crate) fn profile(policy: &Policy) -> String {
    let mut s = String::from("(version 1)\n(deny default)\n");
    s.push_str("(allow process-fork)\n(allow signal (target same-sandbox))\n(allow process-info* (target self))\n");
    s.push_str("(allow sysctl-read)\n(allow file-read-metadata)\n(allow file-read-data (literal \"/\"))\n");
    s.push_str("(allow mach-lookup (global-name \"com.apple.system.logger\"))\n");
    s.push_str("(allow file-write-data (literal \"/dev/null\"))\n");
    let sub = |p: &Path| format!("(subpath {})", quote(&canon(p)));
    let exec: Vec<String> = policy.read_exec.iter().map(|p| sub(p)).collect();
    if !exec.is_empty() {
        s.push_str(&format!("(allow process-exec file-map-executable file-read* {})\n", exec.join(" ")));
    }
    let read: Vec<String> = policy.read.iter().map(|p| sub(p)).collect();
    if !read.is_empty() {
        s.push_str(&format!("(allow file-read* {})\n", read.join(" ")));
    }
    let write: Vec<String> = policy.write.iter().map(|p| sub(p)).collect();
    if !write.is_empty() {
        s.push_str(&format!("(allow file-read* file-write* {})\n", write.join(" ")));
    }
    s
}

pub(crate) struct Prepared {
    pub(crate) profile: String,
    limits: super::Limits,
    keep_fd: RawFd,
}

pub(crate) fn prepare(policy: &Policy, keep_fd: RawFd) -> Result<(Prepared, Report)> {
    let report = probe();
    if policy.require == Require::Full && !report.full() {
        return Err(Error::Sandbox(report.missing.join("; ")));
    }
    for p in &policy.write {
        std::fs::create_dir_all(p).ok();
    }
    Ok((Prepared { profile: profile(policy), limits: policy.limits, keep_fd }, report))
}

fn rlimit(res: libc::c_int, v: u64) -> bool {
    let l = libc::rlimit { rlim_cur: v as libc::rlim_t, rlim_max: v as libc::rlim_t };
    // SAFETY: l is valid.
    unsafe { libc::setrlimit(res, &l) == 0 }
}

impl Prepared {
    /// Runs in the child between fork and exec.
    pub(crate) fn apply(&self) -> std::io::Result<()> {
        // Only the host socket survives exec.
        super::cloexec_all_but(self.keep_fd);
        // SAFETY: plain system calls on integers.
        unsafe {
            if libc::fcntl(self.keep_fd, libc::F_SETFD, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        rlimit(libc::RLIMIT_CORE, 0);
        // RLIMIT_AS is not enforced on macOS; leave it.
        if let Some(c) = self.limits.cpu_secs {
            rlimit(libc::RLIMIT_CPU, c);
        }
        if let Some(n) = self.limits.open_files {
            rlimit(libc::RLIMIT_NOFILE, n);
        }
        Ok(())
    }
}
