mod to_map;
pub use to_map::CefToHashMap;

#[cfg(test)]
mod tests;

mod error;
use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

mod util;
