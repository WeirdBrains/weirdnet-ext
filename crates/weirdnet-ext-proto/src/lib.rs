//! `weirdnet.ext.v1`: the protobuf contract between a Weirdnet extension host and its
//! extensions, with tonic client and server stubs. See `proto/weirdnet/ext/v1/ext.proto`.
//!
//! App-specific services (such as Morph's `morph.ext.v1`) travel inside [`v1::CallRequest`]
//! and [`v1::AppEvent`] as prost-encoded bytes, so this contract stays the same for every app.

/// The session metadata key sent on every call after the handshake.
pub const SESSION_HEADER: &str = "x-weirdnet-session";
/// The environment variable holding the one-time token.
pub const ENV_TOKEN: &str = "WEIRDNET_EXT_TOKEN";
/// The environment variable holding the file descriptor of the extension's end of the
/// private socket the host made for it (Unix). The extension needs no `socket()` call.
pub const ENV_FD: &str = "WEIRDNET_EXT_FD";
/// The environment variable holding a host socket path instead (or a named pipe on Windows).
pub const ENV_SOCKET: &str = "WEIRDNET_EXT_SOCKET";
/// The environment variable holding the extension id.
pub const ENV_ID: &str = "WEIRDNET_EXT_ID";
/// The host API version this contract describes.
pub const API_VERSION: u32 = 1;

/// The generated messages and stubs.
#[allow(missing_docs, clippy::all)]
pub mod v1 {
    tonic::include_proto!("weirdnet.ext.v1");
}

/// tonic's status types, for implementing services without a direct tonic dependency.
pub mod tonic_status {
    pub use tonic::{Code, Status};
}
