use anyhow::Result;
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use reqwest::{Proxy, redirect::Policy};
use std::path::PathBuf;
use std::time::Duration;

pub type HttpClient = reqwest_middleware::ClientWithMiddleware;

pub struct BuildHttpClientArgs {
    pub allow_invalid_certs: bool,
    pub max_redirects: usize,
    pub request_timeout: Duration,
    pub use_request_cache: bool,
    pub proxy: Option<Proxy>,
}

/// Create a new [`HttpClient`] with the given arguments.
pub fn build_http_client(args: BuildHttpClientArgs) -> Result<HttpClient> {
    let mut builder = {
        let mut builder = reqwest::ClientBuilder::default()
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
            .timeout(args.request_timeout);
        if let Some(proxy) = args.proxy {
            builder = builder.proxy(proxy);
        }
        reqwest_middleware::ClientBuilder::new(builder.build()?)
    };

    if args.use_request_cache {
        builder = builder.with(Cache(HttpCache {
            mode: CacheMode::Default,
            manager: CACacheManager::new(
                dirs::cache_dir()
                    .unwrap_or(PathBuf::from(".cache"))
                    .join("aigis")
                    .join("cache"),
                true,
            ),
            options: HttpCacheOptions::default(),
        }));
    }

    Ok(builder.build())
}
