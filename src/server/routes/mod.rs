mod health;
mod index;
mod metadata;
mod proxy;

pub use health::*;
pub use index::*;
pub use metadata::*;
pub use proxy::*;

#[derive(serde::Serialize)]
pub struct ErrorResponse {
    message: &'static str,
}
