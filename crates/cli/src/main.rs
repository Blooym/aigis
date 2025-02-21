use aigis::{
    AigisServer, AigisServerSettings, ProxySettings, UpstreamSettings,
    mime::{IMAGE_STAR, Mime},
    url::Url,
};
use anyhow::Result;
use bytesize::ByteSize;
use clap::Parser;
use dotenvy::dotenv;
use std::{net::SocketAddr, str::FromStr};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about)]
struct AppOptions {
    /// The socket address that the local server should be hosted on.
    #[arg(
        long = "address",
        env = "AIGIS_ADDRESS",
        default_value = "127.0.0.1:3500"
    )]
    address: SocketAddr,

    /// The maximum lifetime of an incoming request before it is forcefully terminated (in seconds).
    #[arg(
        long = "request-timeout",
        env = "AIGIS_REQUEST_TIMEOUT",
        default_value_t = 30
    )]
    request_timeout: u64,

    /// DANGEROUS: Allow self-signed/invalid/forged TLS certificates when making upstream requests.
    #[arg(
        long = "allow-invalid-upstream-certs",
        env = "AIGIS_ALLOW_INVALID_UPSTREAM_CERTS",
        default_value_t = false
    )]
    allow_invalid_upstream_certs: bool,

    /// The maximum lifetime of an upstream request before it is forcefully terminated (in seconds).
    #[arg(
        long = "upstream-request-timeout",
        env = "AIGIS_UPSTEAM_REQUEST_TIMEOUT",
        default_value_t = 10
    )]
    upstream_request_timeout: u64,

    /// The maximum amount of redirects to follow when making upstream requests.
    #[arg(
        long = "upstream-max-redirects",
        env = "AIGIS_UPSTREAM_MAX_REDIRECTS",
        default_value_t = 10
    )]
    upstream_max_redirects: usize,

    /// A list of header names that should be passed from the original request to the upstream if they are set.
    /// Leave empty to not pass any headers.
    #[arg(long = "upstream-pass-headers", env = "AIGIS_UPSTREAM_PASS_HEADERS")]
    upstream_pass_headers: Option<Vec<String>>,

    /// Whether or not to send the client the `Cache-Control` header value that was received when making the
    /// request to the upstream server if one is available.
    ///
    /// If one of the `cache-*` crate features are enabled the request will already be cached server-side for that requested duration,
    /// so sending the `Cache-Control` header to the client is favourable behaviour as it can sometimes lighten server load.
    // https://stackoverflow.com/questions/77771008/
    #[arg(
        long = "use-received-cache-headers",
        env = "AIGIS_USE_RECEIVED_CACHE_HEADERS",
        default_value_t = true
    )]
    use_received_cache_headers: std::primitive::bool,

    /// The maximum Content-Length that can be proxied by this server.
    #[arg(
        long = "max-proxy-size",
        env = "AIGIS_MAX_PROXY_SIZE",
        default_value = "100MB"
    )]
    max_proxy_size: ByteSize,

    /// A list of MIME "essence" strings that are allowed to be proxied by this server.
    /// Supports type wildcards (e.g. 'image/*').
    #[arg(
        long = "allowed-proxy-mimetypes",
        env = "AIGIS_ALLOWED_PROXY_MIMETYPES",
        default_values_t = [
            IMAGE_STAR,
            Mime::from_str("video/*").unwrap()
        ]
    )]
    allowed_proxy_mimetypes: Vec<Mime>,

    /// A list of domains that content is allowed to be proxied.
    /// When left empty all domains are allowed.
    /// Does not support wildcards.
    #[arg(long = "allowed-proxy-domains", env = "AIGIS_ALLOWED_PROXY_DOMAINS")]
    allowed_proxy_domains: Option<Vec<Url>>,

    /// The maximum resolution (inclusive) that is allowed to be requested when proxying
    /// content that supports modification at runtime.
    ///
    /// This only affects content that is explicitly requested at a resolution, not content that is originally
    /// larger than this size.
    #[arg(
        long = "max-proxy-content-rescale-res",
        env = "AIGIS_MAX_CONTENT_RESCALE_RES",
        default_value_t = 1024
    )]
    max_content_rescale_res: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info")))
        .with_thread_ids(true)
        .init();
    let args = AppOptions::parse();

    if args.allow_invalid_upstream_certs {
        println!(
            "WARNING: Running with 'upstream_allow_invalid_certs' will allow upstreams with Invalid/Forged/No TLS certificates to be proxied, be careful."
        );
    }

    AigisServer::new(AigisServerSettings {
        request_timeout: args.request_timeout,
        proxy_settings: ProxySettings {
            allowed_domains: args.allowed_proxy_domains,
            allowed_mimetypes: args.allowed_proxy_mimetypes,
            max_size: args.max_proxy_size.as_u64(),
            max_content_rescale_resolution: args.max_content_rescale_res,
        },
        upstream_settings: UpstreamSettings {
            allow_invalid_certs: args.allow_invalid_upstream_certs,
            max_redirects: args.upstream_max_redirects,
            pass_headers: args.upstream_pass_headers,
            request_timeout: args.request_timeout,
            use_received_cache_headers: args.use_received_cache_headers,
        },
    })?
    .start(&args.address)
    .await
}
