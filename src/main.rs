mod server;

use anyhow::Result;
use bytesize::ByteSize;
use clap::Parser;
use core::net::SocketAddr;
use dotenvy::dotenv;
use mime::{IMAGE_STAR, Mime};
use server::{CacheSettings, ProxySettings, Server, Settings, UpstreamSettings};
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Arguments {
    /// Internet socket address that the server should be ran on.
    #[arg(
        long = "address",
        env = "AIGIS_ADDRESS",
        default_value = "127.0.0.1:3500"
    )]
    address: SocketAddr,

    /// Maximum waiting time for before all incoming requests are aborted.
    #[arg(
        long = "request-timeout",
        env = "AIGIS_REQUEST_TIMEOUT",
        default_value = "15s"
    )]
    request_timeout: humantime::Duration,

    /// The proxy to use when making requests to upstreams. Credentials can be passed as https://user:pass@example.com if needed.
    #[arg(long = "upstream-request-proxy", env = "AIGIS_REQUEST_PROXY")]
    upstream_request_proxy: Option<Url>,

    /// Maximum waiting time before requests to upstreams are aborted.
    #[arg(
        long = "upstream-request-timeout",
        env = "AIGIS_UPSTREAM_REQUEST_TIMEOUT",
        default_value = "10s"
    )]
    upstream_request_timeout: humantime::Duration,

    /// Maximum amount of redirects to follow when making upstream requests before aborting.
    #[arg(
        long = "upstream-max-redirects",
        env = "AIGIS_UPSTREAM_MAX_REDIRECTS",
        default_value_t = 5
    )]
    upstream_max_redirects: usize,

    /// Headers to pass from the original request to the upstream if they are present.
    #[arg(
        long = "upstream-forwarded-headers",
        env = "AIGIS_UPSTREAM_FORWARDED_HEADERS",
        value_delimiter = ','
    )]
    upstream_forwarded_headers: Option<Vec<String>>,

    /// Allow invalid TLS certificates when making upstream requests (DANGEROUS).
    #[arg(
        long = "upstream-allow-invalid-certs",
        env = "AIGIS_UPSTREAM_ALLOW_INVALID_CERTS",
        default_value_t = false
    )]
    upstream_allow_invalid_certs: bool,

    /// Maximum file size that can be proxied by this server.
    ///
    /// This limit is enforced both via the Content-Length header and during download.
    /// If the upstream server provides an inaccurate Content-Length or the actual
    /// content exceeds this limit, the proxy will abort the request.
    #[arg(
        long = "proxy-max-content-length",
        env = "AIGIS_PROXY_MAX_CONTENT_LENGTH",
        default_value = "20MB"
    )]
    proxy_max_content_length: ByteSize,

    /// A list of MIME "essence" strings that are allowed to be proxied by this server.
    /// Supports type wildcards (e.g. 'image/*').
    #[arg(
        long = "proxy-allowed-mimetypes",
        env = "AIGIS_PROXY_ALLOWED_MIMETYPES",
        default_values_t = [
            IMAGE_STAR
        ],
        value_delimiter = ','
    )]
    proxy_allowed_mimetypes: Vec<Mime>,

    /// A list of domains that content is allowed to be proxied.
    /// When left empty all domains are allowed.
    /// Does not support wildcards.
    #[arg(long = "proxy-allowed-domains", env = "AIGIS_PROXY_ALLOWED_DOMAINS")]
    proxy_allowed_domains: Option<Vec<Url>>,

    /// Maximum resolution (inclusive) that is allowed to be requested when proxying
    /// content that supports modification at runtime.
    ///
    /// This only affects content that is explicitly requested at a resolution, not content that is originally
    /// larger than this size.
    #[arg(
        long = "proxy-max-rescale-res",
        env = "AIGIS_PROXY_MAX_RESCALE_RES",
        default_value_t = 1024
    )]
    proxy_max_rescale_res: u32,

    /// Maximum amount of system memory allowed to be used by the cache at any time.
    #[arg(
        long = "cache-max-size",
        env = "AIGIS_CACHE_MAX_SIZE",
        default_value = "1GB"
    )]
    cache_max_size: ByteSize,

    /// Time until a cache entry is considered "idle" and is evicted before it's actual expiry.
    ///
    /// When this is left empty, this behaviour is disabled and expiry will only happen when the item
    /// actually due to expire.
    #[arg(
        long = "cache-time-to-idle",
        env = "AIGIS_CACHE_TIME_TO_IDLE",
        default_value = "1h"
    )]
    cache_time_to_idle: Option<humantime::Duration>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info")))
        .init();
    let args = Arguments::parse();

    if args.upstream_allow_invalid_certs {
        println!(
            "WARNING: Running with 'upstream_allow_invalid_certs' will allow upstreams with Invalid/Forged/No TLS certificates to be proxied, be careful."
        );
    }

    Server::new(Settings {
        request_timeout: *args.request_timeout,
        proxy_settings: ProxySettings {
            allowed_domains: args.proxy_allowed_domains.map(|d| d.into_boxed_slice()),
            allowed_mimetypes: args.proxy_allowed_mimetypes.into_boxed_slice(),
            max_content_length: args.proxy_max_content_length.as_u64(),
            max_rescale_resolution: args.proxy_max_rescale_res,
        },
        upstream_settings: UpstreamSettings {
            allow_invalid_certs: args.upstream_allow_invalid_certs,
            max_redirects: args.upstream_max_redirects,
            forwarded_headers: args
                .upstream_forwarded_headers
                .map(|h| h.into_boxed_slice()),
            request_timeout: *args.request_timeout,
            request_proxy: args.upstream_request_proxy,
        },
        cache_settings: CacheSettings {
            max_size: args.cache_max_size.as_u64(),
            time_to_idle: args.cache_time_to_idle.map(|t| *t),
        },
    })?
    .start(&args.address)
    .await
}
