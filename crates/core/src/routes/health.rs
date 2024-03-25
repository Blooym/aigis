pub const HEALTH_ENDPOINT: &str = "/health";

pub async fn health_handler() -> &'static str {
    "OK"
}
