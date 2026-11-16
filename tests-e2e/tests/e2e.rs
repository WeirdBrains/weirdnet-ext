//! A real extension binary, packaged, installed and run in the sandbox.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use libp2p_identity::Keypair;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use weirdnet_ext::broker::{BoxFuture, CallContext, Need, Services};
use weirdnet_ext::manifest::{self, Capability, Manifest, Native};
use weirdnet_ext::proto::v1::log_record::Level;
use weirdnet_ext::supervisor::{self, Backoff, Config, Status};
use weirdnet_ext::{Grants, Installer, package};

#[derive(Default)]
struct TestServices {
    probe: Mutex<Option<serde_json::Value>>,
    echoes: Mutex<Vec<Vec<u8>>>,
}

impl Services for TestServices {
    fn required(&self, service: &str, method: &str, _: &[u8]) -> Option<Need> {
        match (service, method) {
            ("test.Probe", "Report") => Some(Need::Session),
            ("test.Echo", "Echo") => Some(Need::Capability { name: "echo".into(), target: None }),
            _ => None,
        }
    }

    fn call<'a>(
        &'a self,
        ctx: &'a CallContext,
        service: &'a str,
        _: &'a str,
        payload: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, weirdnet_ext::proto::tonic_status::Status>> {
        Box::pin(async move {
            assert_eq!(ctx.extension_id, "com.example.testext");
            if service == "test.Probe" {
                *self.probe.lock().unwrap() = Some(serde_json::from_slice(&payload).unwrap());
            } else {
                self.echoes.lock().unwrap().push(payload.clone());
            }
            Ok(payload)
        })
    }
}

struct Env {
    _dir: tempfile::TempDir,
    installer: Installer,
    data: PathBuf,
}

fn install() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("bin")).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_testext"), src.join("bin/testext")).unwrap();
    let m = Manifest {
        format: manifest::FORMAT,
        id: "com.example.testext".into(),
        name: "Test extension".into(),
        version: "1.0.0".into(),
        author: String::new(),
        author_key: String::new(),
        api_version: 1,
        capabilities: vec![Capability::new("echo")],
        sites: vec![],
        native: vec![Native { target: manifest::current_target(), path: "bin/testext".into() }],
        wasm: None,
        files: vec![],
    };
    let bytes = package::build(&src, m, &Keypair::generate_ed25519()).unwrap();
    let installer = Installer::new(dir.path().join("extensions"));
    installer.install(installer.inspect(&bytes).unwrap()).unwrap();
    let data = dir.path().join("data");
    Env { _dir: dir, installer, data }
}

fn config(env: &Env, mode: &str, grants: Grants, services: Arc<TestServices>) -> Config {
    let mut c = Config::new("weirdnet-ext tests", env.installer.clone(), "com.example.testext", &env.data, grants, services);
    c.args = vec![mode.into()];
    c.backoff =
        Backoff { initial: Duration::from_millis(50), max: Duration::from_millis(200), reset_after: Duration::from_secs(30), max_failures: 3 };
    c.stop_grace = Duration::from_millis(500);
    c
}

fn strict() -> bool {
    std::env::var_os("WEIRDNET_EXT_E2E_BEST_EFFORT").is_none()
}

async fn wait_until<T>(mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out");
}

#[tokio::test]
async fn the_sandbox_holds() {
    let env = install();
    let services = Arc::new(TestServices::default());
    let mut c = config(&env, "probe", Grants::none(), services.clone());
    if !strict() {
        let mut p = weirdnet_ext::Policy::for_extension(env.installer.verify("com.example.testext").unwrap().dir, &env.data);
        p.require = weirdnet_ext::Require::BestEffort;
        c.policy = Some(p);
    }
    let h = supervisor::start(c);
    let st = h.wait_for(|s| matches!(s, Status::Running { .. }) || s.is_final()).await;
    let Status::Running { sandbox, .. } = st else { panic!("{st:?}") };
    eprintln!("sandbox: {sandbox:?}");
    let r = wait_until(|| services.probe.lock().unwrap().clone()).await;
    eprintln!("probe: {r:#}");
    let denied = |k: &str| {
        let v = r[k].as_str().unwrap_or("missing");
        assert_ne!(v, "ok", "{k} should be denied");
    };
    let allowed = |k: &str| assert_eq!(r[k], "ok", "{k} should work");
    allowed("read_own");
    allowed("write_data");
    allowed("socketpair_unix");
    for k in ["read_etc_passwd", "read_home", "write_tmp", "write_own", "tcp_connect", "tcp_bind", "unix_connect"] {
        denied(k);
    }
    #[cfg(target_os = "linux")]
    {
        allowed("spawn_thread");
        allowed("spawn_process");
        for k in ["socket_inet", "socketpair_inet", "ptrace", "unshare_user", "io_uring"] {
            denied(k);
        }
        if sandbox.landlock_abi.is_some_and(|a| a >= 6) {
            denied("kill_init");
        }
    }
    let mut env_keys: Vec<String> = r["env"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    env_keys.retain(|k| !k.starts_with("__CF") && k != "PWD" && k != "SHLVL" && k != "_");
    assert_eq!(env_keys, ["HOME", "RUST_BACKTRACE", "TMPDIR", "WEIRDNET_EXT_FD", "WEIRDNET_EXT_ID", "WEIRDNET_EXT_TOKEN"]);
    // stdin, stdout, stderr and the host socket.
    let fds: Vec<i64> = r["fds"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
    let sock: i64 = r["socket_fd"].as_str().unwrap().parse().unwrap();
    assert_eq!(fds, [0, 1, 2, sock], "inherited descriptors");
    assert!(!Path::new("/tmp/weirdnet-ext-escape").exists());
    assert_eq!(std::fs::read(env.data.join("note.txt")).unwrap(), b"hi");
    h.stop("done").await;
    assert_eq!(h.status(), Status::Stopped { reason: "done".into() });
}

#[tokio::test]
async fn calls_follow_the_grants_and_logs_and_health_arrive() {
    let env = install();
    let services = Arc::new(TestServices::default());
    let (logs_tx, mut logs) = tokio::sync::mpsc::channel(64);
    let mut c = config(&env, "echo", Grants(vec![Capability::new("echo")]), services.clone());
    c.logs = Some(logs_tx);
    let h = supervisor::start(c);
    let l = logs.recv().await.unwrap();
    assert_eq!((l.level, l.message.as_str()), (Level::Info, "testext up"));
    assert_eq!(l.fields, vec![("mode".to_string(), "echo".to_string())]);
    wait_until(|| h.health()).await;
    h.send("test.Hello", b"one".to_vec()).await;
    assert_eq!(logs.recv().await.unwrap().message, "echo test.Hello: ok");
    assert_eq!(*services.echoes.lock().unwrap(), vec![b"one".to_vec()]);
    // Revoked: the next call is refused.
    h.set_grants(Grants::none()).await;
    h.send("test.Hello", b"two".to_vec()).await;
    assert_eq!(
        logs.recv().await.unwrap().message,
        "echo test.Hello: Client specified an invalid argument"
            .replace("Client specified an invalid argument", &weirdnet_ext::proto::tonic_status::Code::PermissionDenied.to_string())
    );
    assert_eq!(services.echoes.lock().unwrap().len(), 1);
    h.ping(7).await;
    wait_until(|| h.health().filter(|r| r.ping == 7)).await;
    h.stop("done").await;
}

#[tokio::test]
async fn crashes_restart_with_backoff_then_give_up() {
    let env = install();
    let h = supervisor::start(config(&env, "crash", Grants::none(), Arc::default()));
    let mut w = h.watch();
    let mut restarts = vec![];
    loop {
        w.changed().await.unwrap();
        let s = w.borrow().clone();
        match s {
            Status::Restarting { exit, after } => {
                assert_eq!(exit, "exit code 3");
                restarts.push(after);
            }
            Status::Failed { error } => {
                assert!(error.contains("crashed 3 times"), "{error}");
                break;
            }
            Status::Stopped { .. } => panic!("stopped"),
            _ => {}
        }
    }
    assert_eq!(restarts, vec![Duration::from_millis(50), Duration::from_millis(100)]);
}

#[tokio::test]
async fn a_stuck_extension_is_killed_after_the_grace_period() {
    let env = install();
    let h = supervisor::start(config(&env, "hang", Grants::none(), Arc::default()));
    let Status::Running { pid, .. } = h.wait_for(|s| matches!(s, Status::Running { .. })).await else { unreachable!() };
    wait_until(|| h.health()).await;
    let t = std::time::Instant::now();
    h.stop("bye").await;
    assert!(t.elapsed() >= Duration::from_millis(450));
    // SAFETY: probing a pid.
    assert_ne!(unsafe { libc_kill(pid as i32, 0) }, 0, "the process is gone");
}

#[tokio::test]
async fn idle_extensions_stop() {
    let env = install();
    let mut c = config(&env, "echo", Grants::none(), Arc::default());
    c.idle = Some(Duration::from_millis(300));
    let h = supervisor::start(c);
    assert_eq!(h.wait_for(Status::is_final).await, Status::Stopped { reason: "idle".into() });
}

#[tokio::test]
async fn a_tampered_install_does_not_start() {
    let env = install();
    let i = env.installer.verify("com.example.testext").unwrap();
    let bin = i.native().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut b = std::fs::read(&bin).unwrap();
    let n = b.len();
    b[n - 1] ^= 1;
    std::fs::write(&bin, b).unwrap();
    let h = supervisor::start(config(&env, "echo", Grants::none(), Arc::default()));
    match h.wait_for(Status::is_final).await {
        Status::Failed { error } => assert!(error.contains("does not match"), "{error}"),
        s => panic!("{s:?}"),
    }
}

unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}
