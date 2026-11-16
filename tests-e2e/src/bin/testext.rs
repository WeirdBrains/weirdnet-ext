//! A test extension. `probe` tries what the sandbox should stop and reports; `crash` exits
//! with an error after the handshake; `echo` sends app events back through a host call;
//! `hang` ignores Stop.

use serde_json::json;
use std::io::Write;
use weirdnet_ext_sdk::{Event, Extension, Level};

fn errno<T>(r: std::io::Result<T>) -> serde_json::Value {
    match r {
        Ok(_) => json!("ok"),
        Err(e) => json!(e.raw_os_error().map(|c| format!("errno {c}")).unwrap_or(e.to_string())),
    }
}

fn sys(r: libc::c_long) -> serde_json::Value {
    if r < 0 { json!(format!("errno {}", std::io::Error::last_os_error().raw_os_error().unwrap_or(0))) } else { json!("ok") }
}

/// The descriptors open at start, before the runtime opens its own.
static FDS: std::sync::OnceLock<Vec<i32>> = std::sync::OnceLock::new();

fn open_fds() -> Vec<i32> {
    // SAFETY: F_GETFD only reads.
    (0..1024).filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0).collect()
}

fn probe(data: &str, own: &str) -> serde_json::Value {
    let mut r = serde_json::Map::new();
    r.insert("read_etc_passwd".into(), errno(std::fs::read("/etc/passwd")));
    r.insert("read_home".into(), errno(std::fs::read_dir("/home")));
    r.insert("read_own".into(), errno(std::fs::read(own)));
    r.insert("write_data".into(), errno(std::fs::File::create(format!("{data}/note.txt")).and_then(|mut f| f.write_all(b"hi"))));
    r.insert("write_tmp".into(), errno(std::fs::write("/tmp/weirdnet-ext-escape", b"x")));
    r.insert("write_own".into(), errno(std::fs::write(own, b"x")));
    r.insert("tcp_connect".into(), errno(std::net::TcpStream::connect("1.1.1.1:443")));
    r.insert("tcp_bind".into(), errno(std::net::TcpListener::bind("127.0.0.1:0")));
    #[cfg(unix)]
    r.insert("unix_connect".into(), errno(std::os::unix::net::UnixStream::connect("/run/dbus/system_bus_socket")));
    #[cfg(unix)]
    r.insert("socketpair_unix".into(), errno(std::os::unix::net::UnixStream::pair()));
    #[cfg(target_os = "linux")]
    {
        // SAFETY: test probes of system calls the sandbox should deny.
        unsafe {
            r.insert("socket_inet".into(), sys(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) as libc::c_long));
            r.insert("socketpair_inet".into(), sys(libc::socketpair(libc::AF_INET, libc::SOCK_STREAM, 0, [0i32; 2].as_mut_ptr()) as libc::c_long));
            r.insert("ptrace".into(), sys(libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0)));
            r.insert("unshare_user".into(), sys(libc::unshare(libc::CLONE_NEWUSER) as libc::c_long));
            r.insert("io_uring".into(), sys(libc::syscall(libc::SYS_io_uring_setup, 1, [0u8; 120].as_mut_ptr())));
            r.insert("kill_init".into(), sys(libc::kill(1, 0) as libc::c_long));
        }
        r.insert("spawn_thread".into(), errno(std::thread::spawn(|| 1).join().map_err(|_| std::io::Error::other("join"))));
        r.insert("spawn_process".into(), errno(std::process::Command::new(std::env::current_exe().unwrap()).arg("noop").status()));
    }
    r.insert("fds".into(), json!(*FDS.get().unwrap()));
    r.insert("socket_fd".into(), json!(std::env::var("WEIRDNET_EXT_FD").unwrap()));
    let mut env: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    env.sort();
    r.insert("env".into(), json!(env));
    serde_json::Value::Object(r)
}

fn main() {
    FDS.set(open_fds()).unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(run());
}

async fn run() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "noop" {
        return;
    }
    let ext = match Extension::connect("1.0.0").await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("testext: {e}");
            std::process::exit(2);
        }
    };
    ext.log(Level::Info, "testext up", &[("mode", &mode)]).await.unwrap();
    match mode.as_str() {
        "crash" => std::process::exit(3),
        "probe" => {
            let data = std::env::var("HOME").unwrap();
            let own = std::env::current_exe().unwrap().display().to_string();
            let report = probe(&data, &own);
            ext.call("test.Probe", "Report", serde_json::to_vec(&report).unwrap()).await.unwrap();
        }
        _ => {}
    }
    let e = ext.clone();
    let hang = mode == "hang";
    ext.run(move |ev| {
        let e = e.clone();
        async move {
            match ev {
                Event::App { kind, payload } => {
                    let r = e.call("test.Echo", "Echo", payload).await;
                    let _ = e
                        .log(Level::Info, format!("echo {kind}: {}", r.map(|_| "ok".to_string()).unwrap_or_else(|s| s.code().to_string())), &[])
                        .await;
                }
                Event::Stop { .. } if hang => loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                },
                _ => {}
            }
        }
    })
    .await
    .ok();
}
