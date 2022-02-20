use std::fmt;

pub enum Error {
    NotCef,
    Generic(String),
    Regex(String),
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error::Generic(err.to_string())
    }
}

impl From<fancy_regex::Error> for Error {
    fn from(err: fancy_regex::Error) -> Error {
        Error::Regex(err.to_string())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Generic(msg) => write!(f, "Generic Error: {}", msg)?,
            Error::Regex(msg) => write!(f, "Regex Error: {}", msg)?,
            Error::NotCef => write!(f, "Not a CEF String")?,
        }
        Ok(())
    }
}
