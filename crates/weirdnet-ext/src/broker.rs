//! The broker: the host side of `weirdnet.ext.v1.Host` for one extension session.
//!
//! The handshake takes the one-time token the process was started with (compared in constant
//! time, then spent), checks the extension id, and returns a fresh session id that every
//! later call must carry in `x-weirdnet-session`. Calls go to the app's [`Services`] only if
//! the capability they need is granted right now; a revoked capability fails the next call.

use crate::grants::Grants;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, watch};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use weirdnet_ext_proto::v1::{self, host_server::Host};
use weirdnet_ext_proto::{API_VERSION, SESSION_HEADER};

/// What a call needs before it reaches the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Need {
    /// Nothing beyond a session.
    Session,
    /// A granted capability, for a target (URL or site) if the call has one.
    Capability {
        /// The capability name.
        name: String,
        /// The target the call acts on.
        target: Option<String>,
    },
}

/// Who is calling.
#[derive(Debug, Clone)]
pub struct CallContext {
    /// The extension id.
    pub extension_id: String,
    /// Its version.
    pub version: String,
    /// The grants at the time of the call.
    pub grants: Grants,
}

/// A boxed future, for [`Services`].
pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The app's services behind `Host.Call` (such as Morph's `morph.ext.v1`).
pub trait Services: Send + Sync + 'static {
    /// What `service`/`method` needs, or `None` if there is no such method (the call fails
    /// with `UNIMPLEMENTED`). Decode `payload` to find the target if the method has one.
    fn required(&self, service: &str, method: &str, payload: &[u8]) -> Option<Need>;

    /// Runs a call that passed the check.
    fn call<'a>(&'a self, ctx: &'a CallContext, service: &'a str, method: &'a str, payload: Vec<u8>) -> BoxFuture<'a, Result<Vec<u8>, Status>>;
}

/// No services: every call is `UNIMPLEMENTED`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoServices;

impl Services for NoServices {
    fn required(&self, _: &str, _: &str, _: &[u8]) -> Option<Need> {
        None
    }
    fn call<'a>(&'a self, _: &'a CallContext, _: &'a str, _: &'a str, _: Vec<u8>) -> BoxFuture<'a, Result<Vec<u8>, Status>> {
        Box::pin(async { Err(Status::unimplemented("no services")) })
    }
}

/// A log line from an extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// The level.
    pub level: v1::log_record::Level,
    /// The message.
    pub message: String,
    /// Structured fields.
    pub fields: Vec<(String, String)>,
}

pub(crate) struct Shared {
    pub(crate) started: Instant,
    pub(crate) last_activity: AtomicU64,
    pub(crate) health: watch::Sender<Option<v1::HealthReport>>,
    pub(crate) logs: Option<mpsc::Sender<LogLine>>,
}

impl Shared {
    pub(crate) fn touch(&self) {
        self.last_activity.store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

pub(crate) struct Broker {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) host: String,
    token: Mutex<Option<String>>,
    session: Mutex<Option<String>>,
    grants: watch::Receiver<Grants>,
    events: Mutex<Option<mpsc::Receiver<v1::Event>>>,
    services: Arc<dyn Services>,
    shared: Arc<Shared>,
}

pub(crate) fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("system randomness");
    hex::encode(b)
}

impl Broker {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: String,
        version: String,
        host: String,
        token: String,
        grants: watch::Receiver<Grants>,
        events: mpsc::Receiver<v1::Event>,
        services: Arc<dyn Services>,
        shared: Arc<Shared>,
    ) -> Self {
        Self {
            id,
            version,
            host,
            token: Mutex::new(Some(token)),
            session: Mutex::new(None),
            grants,
            events: Mutex::new(Some(events)),
            services,
            shared,
        }
    }

    fn check_session<T>(&self, req: &Request<T>) -> Result<(), Status> {
        let got = req.metadata().get(SESSION_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
        let ok = match &*self.session.lock().unwrap() {
            Some(s) => bool::from(s.as_bytes().ct_eq(got.as_bytes())),
            None => false,
        };
        if ok {
            self.shared.touch();
            Ok(())
        } else {
            Err(Status::unauthenticated("no session"))
        }
    }
}

type EventStream = Pin<Box<dyn Stream<Item = Result<v1::Event, Status>> + Send>>;

#[tonic::async_trait]
impl Host for Broker {
    async fn handshake(&self, req: Request<v1::HandshakeRequest>) -> Result<Response<v1::HandshakeReply>, Status> {
        let r = req.into_inner();
        {
            let mut t = self.token.lock().unwrap();
            let ok = t.as_ref().is_some_and(|t| bool::from(t.as_bytes().ct_eq(r.token.as_bytes())));
            if !ok {
                return Err(Status::unauthenticated("bad or spent token"));
            }
            *t = None;
        }
        if r.extension_id != self.id {
            return Err(Status::permission_denied("this session is for another extension"));
        }
        if r.api_version == 0 {
            return Err(Status::failed_precondition("api_version 0"));
        }
        let session = random_hex(32);
        *self.session.lock().unwrap() = Some(session.clone());
        self.shared.touch();
        tracing::debug!(ext = %self.id, version = %r.version, sdk = %r.sdk, "extension handshake");
        Ok(Response::new(v1::HandshakeReply {
            session,
            api_version: r.api_version.min(API_VERSION),
            granted: self.grants.borrow().to_proto(),
            host: self.host.clone(),
        }))
    }

    type EventsStream = EventStream;

    async fn events(&self, req: Request<v1::EventsRequest>) -> Result<Response<Self::EventsStream>, Status> {
        self.check_session(&req)?;
        let rx = self.events.lock().unwrap().take().ok_or_else(|| Status::already_exists("the events stream is already open"))?;
        let s = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(tokio_stream::StreamExt::map(s, Ok))))
    }

    async fn call(&self, req: Request<v1::CallRequest>) -> Result<Response<v1::CallReply>, Status> {
        self.check_session(&req)?;
        let r = req.into_inner();
        let grants = self.grants.borrow().clone();
        match self.services.required(&r.service, &r.method, &r.payload) {
            None => return Err(Status::unimplemented(format!("{}/{}", r.service, r.method))),
            Some(Need::Session) => {}
            Some(Need::Capability { name, target }) => {
                if !grants.allows(&name, target.as_deref()) {
                    return Err(Status::permission_denied(format!(
                        "{name} is not granted{}",
                        target.map(|t| format!(" for {t}")).unwrap_or_default()
                    )));
                }
            }
        }
        let ctx = CallContext { extension_id: self.id.clone(), version: self.version.clone(), grants };
        let payload = self.services.call(&ctx, &r.service, &r.method, r.payload).await?;
        Ok(Response::new(v1::CallReply { payload }))
    }

    async fn log(&self, req: Request<v1::LogRecord>) -> Result<Response<v1::Empty>, Status> {
        self.check_session(&req)?;
        let r = req.into_inner();
        let level = r.level();
        let mut msg = r.message;
        msg.truncate(16 << 10);
        let mut fields: Vec<(String, String)> = r.fields.into_iter().take(32).collect();
        fields.sort();
        use v1::log_record::Level as L;
        match level {
            L::Error => tracing::error!(ext = %self.id, ?fields, "{msg}"),
            L::Warn => tracing::warn!(ext = %self.id, ?fields, "{msg}"),
            L::Info => tracing::info!(ext = %self.id, ?fields, "{msg}"),
            L::Debug => tracing::debug!(ext = %self.id, ?fields, "{msg}"),
            _ => tracing::trace!(ext = %self.id, ?fields, "{msg}"),
        }
        if let Some(l) = &self.shared.logs {
            let _ = l.try_send(LogLine { level, message: msg, fields });
        }
        Ok(Response::new(v1::Empty {}))
    }

    async fn health(&self, req: Request<v1::HealthReport>) -> Result<Response<v1::Empty>, Status> {
        self.check_session(&req)?;
        let _ = self.shared.health.send(Some(req.into_inner()));
        Ok(Response::new(v1::Empty {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Capability;

    fn broker() -> (Broker, watch::Sender<Grants>) {
        let (gtx, grx) = watch::channel(Grants(vec![Capability::new("echo")]));
        let (_etx, erx) = mpsc::channel(1);
        let shared = Arc::new(Shared { started: Instant::now(), last_activity: AtomicU64::new(0), health: watch::channel(None).0, logs: None });
        (Broker::new("com.example.x".into(), "1.0.0".into(), "test".into(), "tok".into(), grx, erx, Arc::new(Echo), shared), gtx)
    }

    struct Echo;
    impl Services for Echo {
        fn required(&self, s: &str, _: &str, _: &[u8]) -> Option<Need> {
            (s == "echo").then(|| Need::Capability { name: "echo".into(), target: None })
        }
        fn call<'a>(&'a self, _: &'a CallContext, _: &'a str, _: &'a str, p: Vec<u8>) -> BoxFuture<'a, Result<Vec<u8>, Status>> {
            Box::pin(async move { Ok(p) })
        }
    }

    fn hs(token: &str, id: &str) -> Request<v1::HandshakeRequest> {
        Request::new(v1::HandshakeRequest {
            token: token.into(),
            extension_id: id.into(),
            version: "1.0.0".into(),
            api_version: 9,
            sdk: String::new(),
        })
    }

    fn call(session: Option<&str>, service: &str) -> Request<v1::CallRequest> {
        let mut r = Request::new(v1::CallRequest { service: service.into(), method: "M".into(), payload: b"p".to_vec() });
        if let Some(s) = session {
            r.metadata_mut().insert(SESSION_HEADER, s.parse().unwrap());
        }
        r
    }

    #[tokio::test]
    async fn tokens_sessions_and_grants() {
        let (b, gtx) = broker();
        assert_eq!(b.call(call(None, "echo")).await.unwrap_err().code(), tonic::Code::Unauthenticated);
        assert_eq!(b.handshake(hs("nope", "com.example.x")).await.unwrap_err().code(), tonic::Code::Unauthenticated);
        let r = b.handshake(hs("tok", "com.example.x")).await.unwrap().into_inner();
        assert_eq!(r.api_version, API_VERSION);
        assert_eq!(r.granted.len(), 1);
        // The token is spent.
        assert_eq!(b.handshake(hs("tok", "com.example.x")).await.unwrap_err().code(), tonic::Code::Unauthenticated);
        assert_eq!(b.call(call(Some("0000"), "echo")).await.unwrap_err().code(), tonic::Code::Unauthenticated);
        assert_eq!(b.call(call(Some(&r.session), "echo")).await.unwrap().into_inner().payload, b"p");
        assert_eq!(b.call(call(Some(&r.session), "other")).await.unwrap_err().code(), tonic::Code::Unimplemented);
        gtx.send_replace(Grants::none());
        assert_eq!(b.call(call(Some(&r.session), "echo")).await.unwrap_err().code(), tonic::Code::PermissionDenied);
        // One events stream per session.
        let mut e = Request::new(v1::EventsRequest {});
        e.metadata_mut().insert(SESSION_HEADER, r.session.parse().unwrap());
        assert!(b.events(e).await.is_ok());
        let mut e = Request::new(v1::EventsRequest {});
        e.metadata_mut().insert(SESSION_HEADER, r.session.parse().unwrap());
        assert_eq!(b.events(e).await.err().unwrap().code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn the_token_is_for_one_extension() {
        let (b, _g) = broker();
        assert_eq!(b.handshake(hs("tok", "com.example.y")).await.unwrap_err().code(), tonic::Code::PermissionDenied);
    }
}
