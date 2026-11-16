/// Errors from policy changes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A name or value is not valid.
    #[error("invalid {what}: {msg}")]
    Invalid {
        /// What.
        what: &'static str,
        /// Why.
        msg: String,
    },
    /// The actor may not do this.
    #[error("not allowed: {0}")]
    Denied(String),
}

impl Error {
    pub(crate) fn invalid(what: &'static str, msg: impl Into<String>) -> Self {
        Error::Invalid { what, msg: msg.into() }
    }
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
