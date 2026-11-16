#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
// Native extensions run on Unix only for now; the rest still builds elsewhere.
#![cfg_attr(not(unix), allow(unused))]

pub mod broker;
mod error;
pub mod grants;
pub mod manifest;
pub mod package;
pub mod sandbox;
mod store;
pub mod supervisor;

pub use broker::{CallContext, Need, NoServices, Services};
pub use error::{Error, Result};
pub use grants::Grants;
pub use manifest::{Capability, Manifest};
pub use package::{Installed, Installer, Package, Plan};
pub use sandbox::{Policy, Report, Require};
pub use supervisor::{Config, Handle, Status};
pub use weirdnet_ext_proto as proto;
