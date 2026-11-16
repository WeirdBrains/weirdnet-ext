#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
// Native extensions run on Unix only for now; the rest still builds elsewhere.
#![cfg_attr(not(unix), allow(unused))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
#[cfg(unix)]
use tonic::transport::Endpoint;
use weirdnet_ext_proto::v1::{self, host_client::HostClient};
#[cfg(unix)]
use weirdnet_ext_proto::{API_VERSION, ENV_FD};
use weirdnet_ext_proto::{ENV_ID, ENV_TOKEN, SESSION_HEADER};

pub use tonic::Status;
pub use weirdnet_ext_proto as proto;
pub use weirdnet_ext_proto::v1::health_report::State;
pub use weirdnet_ext_proto::v1::log_record::Level;

/// Errors from connecting.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Not started by a Weirdnet host (an environment variable is missing or bad).
    #[error("not started by a Weirdnet extension host: {0}")]
    NotHosted(String),
    /// The connection failed.
    #[error("connecting to the host: {0}")]
    Transport(#[from] tonic::transport::Error),
    /// The host refused the handshake.
    #[error("handshake: {0}")]
    Handshake(#[from] Status),
    /// An I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Adds the session header to every call.
#[derive(Clone)]
pub struct Session(MetadataValue<Ascii>);

impl Interceptor for Session {
    fn call(&mut self, mut r: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        r.metadata_mut().insert(SESSION_HEADER, self.0.clone());
        Ok(r)
    }
}

/// The client type, for calls this crate has no helper for.
pub type Client = HostClient<InterceptedService<Channel, Session>>;

/// A capability the user granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Its name.
    pub name: String,
    /// The patterns it is limited to (empty: unrestricted).
    pub patterns: Vec<String>,
}

fn caps(v: Vec<v1::Capability>) -> Vec<Capability> {
    v.into_iter().map(|c| Capability { name: c.name, patterns: c.patterns }).collect()
}

/// What an extension gets from its host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// An app event (such as `morph.ext.v1.PageLoaded`), prost-encoded.
    App {
        /// The fully qualified message name.
        kind: String,
        /// The encoded message.
        payload: Vec<u8>,
    },
    /// The grants changed.
    Grants(Vec<Capability>),
    /// Stop now (the process is killed after `grace_ms`).
    Stop {
        /// Why.
        reason: String,
        /// How long until the kill.
        grace_ms: u32,
    },
}

/// A connected extension.
#[derive(Clone)]
pub struct Extension {
    client: Client,
    id: String,
    host: String,
    api_version: u32,
    granted: Arc<Mutex<Vec<Capability>>>,
}

#[cfg(unix)]
fn take_stream() -> Result<tokio::net::UnixStream, Error> {
    use std::os::fd::FromRawFd;
    let fd: i32 = std::env::var(ENV_FD)
        .map_err(|_| Error::NotHosted(format!("{ENV_FD} is not set")))?
        .parse()
        .map_err(|_| Error::NotHosted(format!("{ENV_FD} is not a number")))?;
    if fd < 3 {
        return Err(Error::NotHosted(format!("{ENV_FD} is not a socket")));
    }
    // SAFETY: the host passed this descriptor for us alone; it is taken once (see `connect`).
    let s = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    // Not inherited by anything this process starts.
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }
    s.set_nonblocking(true)?;
    Ok(tokio::net::UnixStream::from_std(s)?)
}

static TAKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Extension {
    /// Connects to the host that started this process and does the handshake. Call once;
    /// `version` is the extension's version from its manifest.
    pub async fn connect(version: &str) -> Result<Self, Error> {
        let id = std::env::var(ENV_ID).map_err(|_| Error::NotHosted(format!("{ENV_ID} is not set")))?;
        let token = std::env::var(ENV_TOKEN).map_err(|_| Error::NotHosted(format!("{ENV_TOKEN} is not set")))?;
        if TAKEN.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::NotHosted("already connected".into()));
        }
        #[cfg(unix)]
        let stream = take_stream()?;
        #[cfg(not(unix))]
        {
            let _ = (version, token);
            return Err(Error::NotHosted("native extensions don't run on this OS yet".into()));
        }
        #[cfg(unix)]
        {
            let slot = Arc::new(Mutex::new(Some(stream)));
            let channel = Endpoint::from_static("http://weirdnet-ext.host")
                .connect_with_connector(tower::service_fn(move |_| {
                    let s = slot.lock().unwrap().take();
                    async move {
                        s.map(hyper_util::rt::TokioIo::new)
                            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "the host connection is closed"))
                    }
                }))
                .await?;
            let mut raw = HostClient::new(channel.clone());
            let r = raw
                .handshake(v1::HandshakeRequest {
                    token,
                    extension_id: id.clone(),
                    version: version.into(),
                    api_version: API_VERSION,
                    sdk: concat!("weirdnet-ext-sdk ", env!("CARGO_PKG_VERSION")).into(),
                })
                .await?
                .into_inner();
            let session = MetadataValue::try_from(r.session.as_str()).map_err(|_| Error::NotHosted("bad session".into()))?;
            let client = HostClient::with_interceptor(channel, Session(session));
            Ok(Self { client, id, host: r.host, api_version: r.api_version, granted: Arc::new(Mutex::new(caps(r.granted))) })
        }
    }

    /// This extension's id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The host app ("morph 0.5.0").
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The API version in use.
    pub fn api_version(&self) -> u32 {
        self.api_version
    }

    /// What is granted now.
    pub fn granted(&self) -> Vec<Capability> {
        self.granted.lock().unwrap().clone()
    }

    /// True if `name` is granted (for some target).
    pub fn has(&self, name: &str) -> bool {
        self.granted.lock().unwrap().iter().any(|c| c.name == name)
    }

    /// The raw client.
    pub fn client(&self) -> Client {
        self.client.clone()
    }

    /// Calls an app service method with a prost-encoded request.
    pub async fn call(&self, service: &str, method: &str, payload: Vec<u8>) -> Result<Vec<u8>, Status> {
        let r = self.client.clone().call(v1::CallRequest { service: service.into(), method: method.into(), payload }).await?;
        Ok(r.into_inner().payload)
    }

    /// Logs a line through the host.
    pub async fn log(&self, level: Level, message: impl Into<String>, fields: &[(&str, &str)]) -> Result<(), Status> {
        let fields: HashMap<String, String> = fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        self.client.clone().log(v1::LogRecord { level: level as i32, message: message.into(), fields }).await?;
        Ok(())
    }

    /// Reports health.
    pub async fn health(&self, state: State, detail: impl Into<String>) -> Result<(), Status> {
        self.client.clone().health(v1::HealthReport { state: state as i32, detail: detail.into(), ping: 0 }).await?;
        Ok(())
    }

    /// Runs the event loop: answers pings, keeps the grants current, and gives app events to
    /// `on_event`; returns on Stop (or when the host goes away). Reports `READY` first.
    pub async fn run<F, Fut>(&self, mut on_event: F) -> Result<Option<String>, Status>
    where
        F: FnMut(Event) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let mut s = self.client.clone().events(v1::EventsRequest {}).await?.into_inner();
        self.health(State::Ready, "").await?;
        use v1::event::Kind;
        while let Some(e) = s.message().await? {
            match e.kind {
                Some(Kind::Ping(p)) => {
                    self.client.clone().health(v1::HealthReport { state: State::Ready as i32, detail: String::new(), ping: p.seq }).await?;
                }
                Some(Kind::Grants(g)) => {
                    let c = caps(g.granted);
                    *self.granted.lock().unwrap() = c.clone();
                    on_event(Event::Grants(c)).await;
                }
                Some(Kind::App(a)) => on_event(Event::App { kind: a.kind, payload: a.payload }).await,
                Some(Kind::Stop(st)) => {
                    on_event(Event::Stop { reason: st.reason.clone(), grace_ms: st.grace_ms }).await;
                    return Ok(Some(st.reason));
                }
                None => {}
            }
        }
        Ok(None)
    }
}
