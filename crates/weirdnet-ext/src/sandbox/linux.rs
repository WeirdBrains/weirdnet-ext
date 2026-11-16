//! Linux: Landlock and seccomp through raw system calls.
//!
//! Everything that allocates (the Landlock ruleset with its rules, the BPF program) is made
//! in the parent before the fork; the child only makes async-signal-safe calls between
//! `fork` and `exec`.

use super::{Policy, Report, Require};
use crate::error::{Error, Result};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

// Landlock (include/uapi/linux/landlock.h).
const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REFER: u64 = 1 << 13;
const FS_TRUNCATE: u64 = 1 << 14;
const FS_IOCTL_DEV: u64 = 1 << 15;
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;
const SCOPE_ABSTRACT_UNIX: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    fs: u64,
    net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed: u64,
    parent_fd: i32,
}

fn fs_rights(abi: u32) -> u64 {
    let mut r = (1u64 << 13) - 1; // EXECUTE ..= MAKE_SYM (ABI 1)
    if abi >= 2 {
        r |= FS_REFER;
    }
    if abi >= 3 {
        r |= FS_TRUNCATE;
    }
    if abi >= 5 {
        r |= FS_IOCTL_DEV;
    }
    r
}

/// The Landlock ABI version, or `None` if Landlock is off or missing.
pub(crate) fn landlock_abi() -> Option<u32> {
    // SAFETY: the documented version query: null attributes, size 0.
    let v = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, CREATE_RULESET_VERSION) };
    (v > 0).then_some(v as u32)
}

fn seccomp_available() -> bool {
    // SAFETY: PR_GET_SECCOMP has no pointer arguments.
    unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 }
}

pub(crate) fn probe() -> Report {
    let abi = landlock_abi();
    let seccomp = seccomp_available();
    let mut r = Report {
        mechanism: "landlock+seccomp",
        landlock_abi: abi,
        files: abi.is_some(),
        network: seccomp || abi.is_some_and(|a| a >= 4),
        syscalls: seccomp,
        ..Default::default()
    };
    if abi.is_none() {
        r.missing.push("Landlock is not enabled (kernel 5.13 or newer with landlock in the lsm= list)".into());
    }
    if !seccomp {
        r.missing.push("seccomp is not available".into());
    }
    if abi.is_some_and(|a| a < 6) {
        r.notes.push("signals to processes outside the sandbox are not limited (Landlock ABI 6, Linux 6.12)".into());
    }
    r
}

/// What the child applies between fork and exec.
pub(crate) struct Prepared {
    ruleset: Option<OwnedFd>,
    filter: Option<Vec<libc::sock_filter>>,
    limits: super::Limits,
    keep_fd: RawFd,
    parent: libc::pid_t,
}

fn add_rule(ruleset: &OwnedFd, path: &std::path::Path, rights: u64, handled: u64) -> Result<bool> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Sandbox("a path has a NUL byte".into()))?;
    // SAFETY: a valid C string; the fd is owned below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Ok(false); // Missing paths are skipped.
    }
    // SAFETY: fd is a fresh descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is valid, st is writable.
    let dir = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let mut allowed = rights & handled;
    if !dir {
        allowed &= FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV;
    }
    let attr = PathBeneath { allowed, parent_fd: fd.as_raw_fd() };
    // SAFETY: attr is a valid landlock_path_beneath_attr.
    let r = unsafe { libc::syscall(libc::SYS_landlock_add_rule, ruleset.as_raw_fd(), RULE_PATH_BENEATH, &attr as *const PathBeneath, 0u32) };
    if r != 0 {
        return Err(Error::Sandbox(format!("landlock rule for {}: {}", path.display(), std::io::Error::last_os_error())));
    }
    Ok(true)
}

fn ruleset(policy: &Policy, abi: u32) -> Result<OwnedFd> {
    let fs = fs_rights(abi);
    let attr = RulesetAttr {
        fs,
        net: if abi >= 4 { NET_BIND_TCP | NET_CONNECT_TCP } else { 0 },
        scoped: if abi >= 6 { SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL } else { 0 },
    };
    let size = match abi {
        1..=3 => 8,
        4 | 5 => 16,
        _ => 24,
    };
    // SAFETY: attr is valid for `size` bytes.
    let fd = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, size as usize, 0u32) };
    if fd < 0 {
        return Err(Error::Sandbox(format!("landlock ruleset: {}", std::io::Error::last_os_error())));
    }
    // SAFETY: a fresh descriptor (O_CLOEXEC by the kernel).
    let rs = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    let read = FS_READ_FILE | FS_READ_DIR;
    for p in &policy.read {
        add_rule(&rs, p, read, fs)?;
    }
    for p in &policy.read_exec {
        add_rule(&rs, p, read | FS_EXECUTE, fs)?;
    }
    for p in &policy.write {
        std::fs::create_dir_all(p).ok();
        add_rule(&rs, p, fs & !FS_EXECUTE, fs)?;
    }
    Ok(rs)
}

// seccomp BPF.
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const fn ret_errno(e: i32) -> u32 {
    0x0005_0000 | (e as u32 & 0xffff)
}
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0: u32 = 16;
const OFF_ARG1: u32 = 24;

fn ld(off: u32) -> libc::sock_filter {
    libc::sock_filter { code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, jt: 0, jf: 0, k: off }
}
fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16, jt, jf, k }
}
fn jge(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16, jt, jf, k }
}
fn jset(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16, jt, jf, k }
}
fn ret(k: u32) -> libc::sock_filter {
    libc::sock_filter { code: (libc::BPF_RET | libc::BPF_K) as u16, jt: 0, jf: 0, k }
}

/// System calls an extension never needs.
fn denied() -> Vec<libc::c_long> {
    use libc::*;
    #[allow(unused_mut)]
    let mut v = vec![
        SYS_ptrace,
        SYS_process_vm_readv,
        SYS_process_vm_writev,
        SYS_mount,
        SYS_umount2,
        SYS_pivot_root,
        SYS_chroot,
        SYS_swapon,
        SYS_swapoff,
        SYS_reboot,
        SYS_kexec_load,
        SYS_kexec_file_load,
        SYS_init_module,
        SYS_finit_module,
        SYS_delete_module,
        SYS_bpf,
        SYS_perf_event_open,
        SYS_userfaultfd,
        SYS_keyctl,
        SYS_add_key,
        SYS_request_key,
        SYS_unshare,
        SYS_setns,
        SYS_open_by_handle_at,
        SYS_name_to_handle_at,
        SYS_acct,
        SYS_settimeofday,
        SYS_clock_settime,
        SYS_clock_adjtime,
        SYS_adjtimex,
        SYS_quotactl,
        SYS_mount_setattr,
        SYS_move_mount,
        SYS_open_tree,
        SYS_fsopen,
        SYS_fsconfig,
        SYS_fsmount,
        SYS_fspick,
        SYS_io_uring_setup,
        SYS_io_uring_enter,
        SYS_io_uring_register,
        SYS_landlock_create_ruleset,
        SYS_landlock_add_rule,
        SYS_landlock_restrict_self,
        SYS_pidfd_getfd,
        SYS_kcmp,
        SYS_lookup_dcookie,
        SYS_vhangup,
        SYS_sethostname,
        SYS_setdomainname,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([SYS_iopl, SYS_ioperm, SYS_uselib, SYS_sysfs, SYS__sysctl, SYS_nfsservctl]);
    v
}

/// The filter: right architecture only (no x32 on x86_64), deny the list above with EPERM,
/// `socket()` with EACCES, `socketpair()` except `AF_UNIX`, `clone()` with namespace flags,
/// `clone3()` with ENOSYS (so libc falls back to `clone()`, whose flags the filter can see),
/// and the `TIOCSTI`/`TIOCLINUX` ioctls; allow the rest.
pub(crate) fn filter() -> Vec<libc::sock_filter> {
    let eperm = ret_errno(libc::EPERM);
    let mut f = vec![ld(OFF_ARCH), jeq(AUDIT_ARCH, 1, 0), ret(RET_KILL_PROCESS), ld(OFF_NR)];
    #[cfg(target_arch = "x86_64")]
    f.extend([jge(0x4000_0000, 0, 1), ret(eperm)]);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = jge;
    for nr in denied() {
        f.extend([jeq(nr as u32, 0, 1), ret(eperm)]);
    }
    f.extend([jeq(libc::SYS_socket as u32, 0, 1), ret(ret_errno(libc::EACCES))]);
    f.extend([jeq(libc::SYS_clone3 as u32, 0, 1), ret(ret_errno(libc::ENOSYS))]);
    // Blocks that decide once the number matches.
    let ns = (libc::CLONE_NEWNS | libc::CLONE_NEWCGROUP | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC | libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNET) as u32 | 0x80 /* CLONE_NEWTIME */;
    f.extend([jeq(libc::SYS_clone as u32, 0, 4), ld(OFF_ARG0), jset(ns, 0, 1), ret(eperm), ret(RET_ALLOW)]);
    f.extend([jeq(libc::SYS_socketpair as u32, 0, 4), ld(OFF_ARG0), jeq(libc::AF_UNIX as u32, 0, 1), ret(RET_ALLOW), ret(ret_errno(libc::EACCES))]);
    f.extend([
        jeq(libc::SYS_ioctl as u32, 0, 5),
        ld(OFF_ARG1),
        jeq(libc::TIOCSTI as u32, 2, 0),
        jeq(0x541C /* TIOCLINUX */, 1, 0),
        ret(RET_ALLOW),
        ret(eperm),
    ]);
    f.push(ret(RET_ALLOW));
    f
}

/// Builds what the child applies, checking it against `policy.require`.
pub(crate) fn prepare(policy: &Policy, keep_fd: RawFd) -> Result<(Prepared, Report)> {
    let mut report = probe();
    if policy.require == Require::Full && !report.full() {
        return Err(Error::Sandbox(report.missing.join("; ")));
    }
    let ruleset = match report.landlock_abi {
        Some(abi) => Some(ruleset(policy, abi)?),
        None => None,
    };
    let filter = report.syscalls.then(filter);
    if ruleset.is_none() && filter.is_none() {
        report.mechanism = "none";
    }
    // SAFETY: getpid has no preconditions.
    let parent = unsafe { libc::getpid() };
    Ok((Prepared { ruleset, filter, limits: policy.limits, keep_fd, parent }, report))
}

fn rlimit(res: libc::__rlimit_resource_t, v: u64) -> bool {
    let l = libc::rlimit { rlim_cur: v as libc::rlim_t, rlim_max: v as libc::rlim_t };
    // SAFETY: l is valid.
    unsafe { libc::setrlimit(res, &l) == 0 }
}

impl Prepared {
    /// Runs in the child between fork and exec: async-signal-safe calls only, no allocation.
    pub(crate) fn apply(&self) -> std::io::Result<()> {
        let err = std::io::Error::last_os_error;
        // SAFETY: plain system calls on integers and on memory prepared before the fork.
        unsafe {
            // Only the host socket survives exec.
            libc::syscall(libc::SYS_close_range, 3u32, (self.keep_fd - 1) as u32, 4u32 /* CLOSE_RANGE_CLOEXEC */);
            libc::syscall(libc::SYS_close_range, (self.keep_fd + 1) as u32, u32::MAX, 4u32);
            if libc::fcntl(self.keep_fd, libc::F_SETFD, 0) != 0 {
                return Err(err());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(err());
            }
            if libc::getppid() != self.parent {
                libc::_exit(1);
            }
            rlimit(libc::RLIMIT_CORE, 0);
            if let Some(m) = self.limits.memory
                && !rlimit(libc::RLIMIT_AS, m)
            {
                return Err(err());
            }
            if let Some(c) = self.limits.cpu_secs
                && !rlimit(libc::RLIMIT_CPU, c)
            {
                return Err(err());
            }
            if let Some(n) = self.limits.open_files
                && !rlimit(libc::RLIMIT_NOFILE, n)
            {
                return Err(err());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(err());
            }
            if let Some(rs) = &self.ruleset
                && libc::syscall(libc::SYS_landlock_restrict_self, rs.as_raw_fd(), 0u32) != 0
            {
                return Err(err());
            }
            if let Some(f) = &self.filter {
                let prog = libc::sock_fprog { len: f.len() as u16, filter: f.as_ptr() as *mut libc::sock_filter };
                if libc::syscall(libc::SYS_seccomp, 1u32 /* SECCOMP_SET_MODE_FILTER */, 0u32, &prog as *const libc::sock_fprog) != 0 {
                    return Err(err());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_is_well_formed() {
        let f = filter();
        assert!(f.len() < 4096);
        // Every jump lands inside the program and the program ends in a return.
        for (i, ins) in f.iter().enumerate() {
            if ins.code & 0x07 == libc::BPF_JMP as u16 {
                assert!(i + 1 + (ins.jt.max(ins.jf) as usize) < f.len(), "jump at {i}");
            }
        }
        assert_eq!(f.last().unwrap().code, (libc::BPF_RET | libc::BPF_K) as u16);
    }

    #[test]
    fn probe_reports() {
        let r = probe();
        assert_eq!(r.mechanism, "landlock+seccomp");
        assert_eq!(r.files, r.landlock_abi.is_some());
    }
}
