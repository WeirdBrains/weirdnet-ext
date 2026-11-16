//! The supervisor: starts an installed extension in the sandbox, serves the broker on a
//! private socket pair, restarts it with backoff when it crashes, stops it when idle or
//! asked, and passes events and grant changes to it.
//!
//! Every start checks the installed files again ([`Installer::verify`]), makes a new socket
//! pair and a new one-time token, so a session never outlives its process.

use crate::broker::{Broker, LogLine, Services, Shared, random_hex};
use crate::error::{Error, Result};
use crate::grants::Grants;
use crate::package::Installer;
use crate::sandbox::{self, Policy, Report};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use weirdnet_ext_proto::v1;

/// Restart backoff.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// The first wait.
    pub initial: Duration,
    /// The longest wait (it doubles up to this).
    pub max: Duration,
    /// A run this long resets the backoff.
    pub reset_after: Duration,
    /// Give up after this many crashes in a row (each shorter than `reset_after`).
    pub max_failures: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { initial: Duration::from_secs(1), max: Duration::from_secs(60), reset_after: Duration::from_secs(60), max_failures: 8 }
    }
}

/// How to run an extension.
#[derive(Clone)]
pub struct Config {
    /// The host app and version, told to the extension ("morph 0.5.0").
    pub host: String,
    /// Where the extensions are installed.
    pub installer: Installer,
    /// The extension id.
    pub id: String,
    /// Its data directory (the only place it can write).
    pub data_dir: PathBuf,
    /// Extra arguments for the binary.
    pub args: Vec<String>,
    /// Extra paths or limits; `None` uses [`Policy::for_extension`].
    pub policy: Option<Policy>,
    /// What the user granted.
    pub grants: Grants,
    /// The app's services.
    pub services: Arc<dyn Services>,
    /// Restart backoff.
    pub backoff: Backoff,
    /// Stop after this long without calls or events.
    pub idle: Option<Duration>,
    /// How long a stop waits before killing.
    pub stop_grace: Duration,
    /// Where extension log lines go besides `tracing`.
    pub logs: Option<mpsc::Sender<LogLine>>,
}

impl Config {
    /// A config with defaults: no extra args, the default policy, default backoff, no idle
    /// stop, 3 s stop grace.
    pub fn new(
        host: impl Into<String>,
        installer: Installer,
        id: impl Into<String>,
        data_dir: impl Into<PathBuf>,
        grants: Grants,
        services: Arc<dyn Services>,
    ) -> Self {
        Self {
            host: host.into(),
            installer,
            id: id.into(),
            data_dir: data_dir.into(),
            args: Vec::new(),
            policy: None,
            grants,
            services,
            backoff: Backoff::default(),
            idle: None,
            stop_grace: Duration::from_secs(3),
            logs: None,
        }
    }
}

/// Where an extension is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Being checked and started.
    Starting,
    /// Running.
    Running {
        /// Its process id.
        pid: u32,
        /// How many times it was started.
        starts: u32,
        /// What the sandbox did.
        sandbox: Report,
    },
    /// Crashed; restarting after a wait.
    Restarting {
        /// How it ended.
        exit: String,
        /// The wait.
        after: Duration,
    },
    /// Stopped (asked, idle, or exited cleanly).
    Stopped {
        /// Why.
        reason: String,
    },
    /// Gave up (it can't start, failed its checks, or crashed too often).
    Failed {
        /// Why.
        error: String,
    },
}

impl Status {
    /// True once it won't run again.
    pub fn is_final(&self) -> bool {
        matches!(self, Status::Stopped { .. } | Status::Failed { .. })
    }
}

enum Cmd {
    Stop(String, oneshot::Sender<()>),
    Event(v1::Event),
}

/// A running extension.
#[derive(Clone)]
pub struct Handle {
    cmd: mpsc::Sender<Cmd>,
    status: watch::Receiver<Status>,
    health: watch::Receiver<Option<v1::HealthReport>>,
    grants: Arc<watch::Sender<Grants>>,
}

impl Handle {
    /// The current status.
    pub fn status(&self) -> Status {
        self.status.borrow().clone()
    }

    /// Watches the status.
    pub fn watch(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }

    /// The last health report.
    pub fn health(&self) -> Option<v1::HealthReport> {
        self.health.borrow().clone()
    }

    /// Waits for a status matching `f`.
    pub async fn wait_for(&self, f: impl Fn(&Status) -> bool) -> Status {
        let mut w = self.status.clone();
        w.wait_for(|s| f(s)).await.map(|s| s.clone()).unwrap_or_else(|_| self.status())
    }

    /// Sends an app event (dropped if the extension isn't running).
    pub async fn send(&self, kind: impl Into<String>, payload: Vec<u8>) {
        let e = v1::Event { kind: Some(v1::event::Kind::App(v1::AppEvent { kind: kind.into(), payload })) };
        let _ = self.cmd.send(Cmd::Event(e)).await;
    }

    /// Asks for a health report.
    pub async fn ping(&self, seq: u64) {
        let _ = self.cmd.send(Cmd::Event(v1::Event { kind: Some(v1::event::Kind::Ping(v1::Ping { seq })) })).await;
    }

    /// Replaces the grants: checked on the next call, and told to the extension.
    pub async fn set_grants(&self, g: Grants) {
        let proto = g.to_proto();
        self.grants.send_replace(g);
        let _ = self.cmd.send(Cmd::Event(v1::Event { kind: Some(v1::event::Kind::Grants(v1::Grants { granted: proto })) })).await;
    }

    /// Stops the extension: a Stop event, then a kill after the grace period.
    pub async fn stop(&self, reason: impl Into<String>) {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::Stop(reason.into(), tx)).await.is_ok() {
            let _ = rx.await;
        }
        self.wait_for(Status::is_final).await;
    }
}

/// Starts an extension under supervision.
pub fn start(config: Config) -> Handle {
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (status_tx, status_rx) = watch::channel(Status::Starting);
    let (health_tx, health_rx) = watch::channel(None);
    let grants = Arc::new(watch::channel(config.grants.clone()).0);
    let h = Handle { cmd: cmd_tx, status: status_rx, health: health_rx, grants: grants.clone() };
    tokio::spawn(run(config, cmd_rx, status_tx, health_tx, grants));
    h
}

enum Ended {
    Stopped(String),
    Exited(std::process::ExitStatus, Duration),
}

async fn run(
    config: Config,
    mut cmd: mpsc::Receiver<Cmd>,
    status: watch::Sender<Status>,
    health: watch::Sender<Option<v1::HealthReport>>,
    grants: Arc<watch::Sender<Grants>>,
) {
    let mut starts = 0u32;
    let mut failures = 0u32;
    let mut wait = config.backoff.initial;
    loop {
        status.send_replace(Status::Starting);
        starts += 1;
        let ended = match once(&config, &mut cmd, &status, &health, &grants, starts).await {
            Ok(e) => e,
            Err(e) => {
                status.send_replace(Status::Failed { error: e.to_string() });
                return;
            }
        };
        match ended {
            Ended::Stopped(reason) => {
                status.send_replace(Status::Stopped { reason });
                return;
            }
            Ended::Exited(st, ran) => {
                if st.success() {
                    status.send_replace(Status::Stopped { reason: "exited".into() });
                    return;
                }
                if ran >= config.backoff.reset_after {
                    failures = 0;
                    wait = config.backoff.initial;
                }
                failures += 1;
                if failures >= config.backoff.max_failures {
                    status.send_replace(Status::Failed { error: format!("crashed {failures} times in a row (last: {})", describe(&st)) });
                    return;
                }
                status.send_replace(Status::Restarting { exit: describe(&st), after: wait });
                let sleep = tokio::time::sleep(wait);
                tokio::pin!(sleep);
                loop {
                    tokio::select! {
                        _ = &mut sleep => break,
                        c = cmd.recv() => match c {
                            Some(Cmd::Stop(reason, done)) => {
                                let _ = done.send(());
                                status.send_replace(Status::Stopped { reason });
                                return;
                            }
                            Some(Cmd::Event(_)) => {}
                            None => return,
                        }
                    }
                }
                wait = (wait * 2).min(config.backoff.max);
            }
        }
    }
}

fn describe(st: &std::process::ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(s) = st.signal() {
            return format!("killed by signal {s}");
        }
    }
    match st.code() {
        Some(c) => format!("exit code {c}"),
        None => "ended".into(),
    }
}

#[cfg(unix)]
fn kill_group(pid: u32) {
    // SAFETY: a signal to the process group the child leads.
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(unix)]
async fn once(
    config: &Config,
    cmd: &mut mpsc::Receiver<Cmd>,
    status: &watch::Sender<Status>,
    health: &watch::Sender<Option<v1::HealthReport>>,
    grants: &Arc<watch::Sender<Grants>>,
    starts: u32,
) -> Result<Ended> {
    use std::os::fd::AsRawFd;
    let installed = config.installer.verify(&config.id)?;
    let binary =
        installed.native().ok_or_else(|| Error::Unsupported(format!("{} has no binary for {}", config.id, crate::manifest::current_target())))?;
    let policy = config.policy.clone().unwrap_or_else(|| Policy::for_extension(&installed.dir, &config.data_dir));
    let (host_end, ext_end) = std::os::unix::net::UnixStream::pair()?;
    host_end.set_nonblocking(true)?;
    let token = random_hex(32);
    let fd = ext_end.as_raw_fd();
    let env = vec![
        (weirdnet_ext_proto::ENV_FD.to_string(), fd.to_string()),
        (weirdnet_ext_proto::ENV_TOKEN.to_string(), token.clone()),
        (weirdnet_ext_proto::ENV_ID.to_string(), config.id.clone()),
        ("HOME".to_string(), config.data_dir.display().to_string()),
        ("TMPDIR".to_string(), config.data_dir.display().to_string()),
        ("RUST_BACKTRACE".to_string(), "1".to_string()),
    ];
    let (mut command, report) = sandbox::command(&binary, &config.args, &policy, fd, &env)?;
    let mut child = command.spawn().map_err(|e| Error::Process(format!("starting {}: {e}", binary.display())))?;
    drop(ext_end);
    let pid = child.id().unwrap_or(0);
    let started = Instant::now();

    let (ev_tx, ev_rx) = mpsc::channel(64);
    let shared = Arc::new(Shared { started, last_activity: AtomicU64::new(0), health: health.clone(), logs: config.logs.clone() });
    let broker = Broker::new(
        config.id.clone(),
        installed.manifest.version.clone(),
        config.host.clone(),
        token,
        grants.subscribe(),
        ev_rx,
        config.services.clone(),
        shared.clone(),
    );
    let io = tokio::net::UnixStream::from_std(host_end)?;
    let (shut_tx, shut_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        // One connection; the stream then stays open, because a server whose incoming
        // stream ends shuts its connections down.
        let incoming = tokio_stream::StreamExt::chain(tokio_stream::once(Ok::<_, std::io::Error>(io)), tokio_stream::pending());
        let _ = tonic::transport::Server::builder()
            .add_service(v1::host_server::HostServer::new(broker))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shut_rx.await;
            })
            .await;
    });
    status.send_replace(Status::Running { pid, starts, sandbox: report });

    let idle_tick = config.idle.map(|d| d.min(Duration::from_secs(1)).max(Duration::from_millis(50)));
    let mut tick = tokio::time::interval(idle_tick.unwrap_or(Duration::from_secs(3600)));
    let stop = |reason: String| async move { reason };
    let ended = loop {
        tokio::select! {
            st = child.wait() => {
                let st = st?;
                break Ended::Exited(st, started.elapsed());
            }
            c = cmd.recv() => match c {
                Some(Cmd::Event(e)) => {
                    shared.touch();
                    let _ = ev_tx.try_send(e);
                }
                Some(Cmd::Stop(reason, done)) => {
                    graceful(&mut child, &ev_tx, pid, config.stop_grace, &reason).await;
                    let _ = done.send(());
                    break Ended::Stopped(stop(reason).await);
                }
                None => {
                    graceful(&mut child, &ev_tx, pid, config.stop_grace, "host gone").await;
                    break Ended::Stopped("host gone".into());
                }
            },
            _ = tick.tick(), if config.idle.is_some() => {
                let idle = config.idle.unwrap();
                let last = Duration::from_millis(shared.last_activity.load(Ordering::Relaxed));
                if started.elapsed().saturating_sub(last) >= idle {
                    graceful(&mut child, &ev_tx, pid, config.stop_grace, "idle").await;
                    break Ended::Stopped("idle".into());
                }
            }
        }
    };
    kill_group(pid);
    let _ = shut_tx.send(());
    server.abort();
    Ok(ended)
}

#[cfg(unix)]
async fn graceful(child: &mut tokio::process::Child, ev: &mpsc::Sender<v1::Event>, pid: u32, grace: Duration, reason: &str) {
    let _ = ev.try_send(v1::Event { kind: Some(v1::event::Kind::Stop(v1::Stop { reason: reason.into(), grace_ms: grace.as_millis() as u32 })) });
    if tokio::time::timeout(grace, child.wait()).await.is_err() {
        kill_group(pid);
        let _ = child.wait().await;
    }
}

#[cfg(not(unix))]
async fn once(
    config: &Config,
    _: &mut mpsc::Receiver<Cmd>,
    _: &watch::Sender<Status>,
    _: &watch::Sender<Option<v1::HealthReport>>,
    _: &Arc<watch::Sender<Grants>>,
    _: u32,
) -> Result<Ended> {
    config.installer.verify(&config.id)?;
    Err(Error::Unsupported("native extensions don't run on this OS yet; use the WASM build".into()))
}
