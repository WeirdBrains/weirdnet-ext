/// Errors from the extension host.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A package or manifest is malformed.
    #[error("invalid package: {0}")]
    Invalid(String),
    /// A signature or file hash does not check out.
    #[error("verification failed: {0}")]
    Verify(String),
    /// An update is signed by another author than the installed version.
    #[error("{id} is pinned to another author ({pinned}); this package is signed by {got}")]
    AuthorChanged {
        /// The extension id.
        id: String,
        /// The pinned author's user id.
        pinned: String,
        /// The package author's user id.
        got: String,
    },
    /// An update is not newer than what is installed.
    #[error("{id} {have} is installed; {got} is not newer")]
    NotNewer {
        /// The extension id.
        id: String,
        /// Installed version.
        have: String,
        /// Package version.
        got: String,
    },
    /// The sandbox can't be set up (or isn't available and was required).
    #[error("sandbox: {0}")]
    Sandbox(String),
    /// Native extensions can't run here.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Spawning or supervising a process failed.
    #[error("process: {0}")]
    Process(String),
    /// An I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn invalid(m: impl Into<String>) -> Error {
    Error::Invalid(m.into())
}
