mod health;
mod index;
mod metadata;
mod proxy;

use axum::http::{HeaderName, HeaderValue};
pub use health::*;
pub use index::*;
pub use metadata::*;
pub use proxy::*;

const AIGIS_CACHE_HEADER: HeaderName = HeaderName::from_static("aigis-cache-status");
const AIGIS_CACHE_HEADER_VALUE_HIT: HeaderValue = HeaderValue::from_static("HIT");

#[derive(serde::Serialize)]
pub struct ErrorResponse {
    message: &'static str,
}
