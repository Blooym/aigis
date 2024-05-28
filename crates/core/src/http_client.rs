#[cfg(feature = "cache-moka")]
#[cfg(feature = "cache-cacache")]
compile_error!("You can only enable one caching backend");

use anyhow::Result;
use reqwest::redirect::Policy;
use std::time::Duration;

pub type HttpClient = reqwest_middleware::ClientWithMiddleware;
pub type HttpClientBuilder = reqwest_middleware::ClientBuilder;

pub struct BuildHttpClientArgs {
    pub allow_invalid_certs: bool,
    pub max_redirects: usize,
    pub request_timeout: Duration,
}

impl Default for BuildHttpClientArgs {
    fn default() -> Self {
        Self {
            allow_invalid_certs: false,
            max_redirects: 10,
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// Create a new [`HttpClient`] with the given arguments.
pub fn build_http_client(args: BuildHttpClientArgs) -> Result<HttpClient> {
    let builder = reqwest_middleware::ClientBuilder::new(
        reqwest::ClientBuilder::default()
            .redirect(Policy::limited(args.max_redirects))
            .user_agent(concat!(
                "Mozilla/5.0",
                " ",
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION"),
                ")"
            ))
            .danger_accept_invalid_certs(args.allow_invalid_certs)
            .connect_timeout(Duration::from_secs(5))
            .timeout(args.request_timeout)
            .build()?,
    );

    #[cfg(feature = "cache-moka")]
    let builder = add_cache(builder)?;
    #[cfg(feature = "cache-cacache")]
    let builder = add_cache(builder)?;

    Ok(builder.build())
}

#[cfg(feature = "cache-moka")]
fn add_cache(client: HttpClientBuilder) -> Result<HttpClientBuilder> {
    use http_cache_reqwest::{Cache, CacheMode, HttpCache, HttpCacheOptions, MokaManager};
    Ok(client.with(Cache(HttpCache {
        mode: CacheMode::Default,
        manager: MokaManager::default(),
        options: HttpCacheOptions::default(),
    })))
}

#[cfg(feature = "cache-cacache")]
fn add_cache(client: HttpClientBuilder) -> Result<HttpClientBuilder> {
    use std::path::PathBuf;

    use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
    Ok(client.with(Cache(HttpCache {
        mode: CacheMode::Default,
        manager: CACacheManager {
            path: dirs::cache_dir()
                .unwrap_or(PathBuf::from(".cache"))
                .join("aigis")
                .join("cacache"),
        },
        options: HttpCacheOptions::default(),
    })))
}
