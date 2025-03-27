use std::num::ParseIntError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Not a CEF String")]
    NotCef,
    #[error("Could be a malformed CEF string")]
    MalformedCef,
    #[error("Bad CEF extension: {0}")]
    CefExtension(&'static str),
    #[error("Unable to split at CEF:0 marker")]
    CefSplit,
    #[error("Unable to find `{0}` in CEF string")]
    CharFind(char),
    #[error("Integer Parsing Error")]
    ParseInt(#[from] ParseIntError),
    #[error("Generic Error: {0}")]
    Generic(String),
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self::Generic(err.to_string())
    }
}
