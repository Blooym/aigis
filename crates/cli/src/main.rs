use aigis::{
    mime::{Mime, IMAGE_STAR},
    url::Url,
    AigisServer, AigisServerSettings, ProxySettings, UpstreamSettings,
};
use anyhow::Result;
use bytesize::ByteSize;
use clap::{
    builder::{
        styling::{AnsiColor, Effects},
        Styles,
    },
    Parser,
};
use dotenvy::dotenv;
use std::{net::SocketAddr, str::FromStr};
use tracing_subscriber::EnvFilter;

fn styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::BrightMagenta.on_default() | Effects::BOLD)
        .usage(AnsiColor::BrightMagenta.on_default() | Effects::BOLD)
        .literal(AnsiColor::BrightGreen.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default())
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about, styles = styles())]
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
        long = "upstream-allow-invalid-certs",
        env = "AIGIS_UPSTREAM_ALLOW_INALID_CERTS",
        default_value_t = false
    )]
    upstream_allow_invalid_certs: bool,

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
    #[arg(
        long = "use_received_cache_times",
        env = "AIGIS_UPSTREAM_USE_RECEIVED_CACHE_TIME"
    )]
    use_received_cache_times: bool,

    /// The maximum Content-Length that can be proxied by this server.
    #[arg(
        long = "proxy-max-size",
        env = "AIGIS_PROXY_MAX_SIZE",
        default_value = "100MB"
    )]
    proxy_max_size: ByteSize,

    /// A list of MIME "essence" strings that are allowed to be proxied by this server.
    /// Supports type wildcards (e.g. 'image/*').
    #[arg(
        long = "proxy-allowed-mimetypes",
        env = "AIGIS_PROXY_ALLOWED_MIMETYPES",
        default_values_t = [
            IMAGE_STAR,
            Mime::from_str("video/*").unwrap()
        ]
    )]
    proxy_allowed_mimetypes: Vec<Mime>,

    /// A list of domains that content is allowed to be proxied.
    /// When left empty all domains are allowed.
    /// Does not support wildcards.
    #[arg(long = "proxy-allowed-domains", env = "AIGIS_PROXY_ALLOWED_DOMAINS")]
    proxy_allowed_domains: Option<Vec<Url>>,

    /// The maximum resolution (inclusive) that is allowed to be requested when proxying
    /// content that supports modification at runtime.
    #[arg(
        long = "proxy-max-upscale-res",
        env = "AIGIS_PROXY_IMAGE_MAX_UPSCALE_RES",
        default_value_t = 1024
    )]
    proxy_max_upscale_res: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info")))
        .with_thread_ids(true)
        .init();
    let args = AppOptions::parse();

    if args.upstream_allow_invalid_certs {
        println!("WARNING: Running with 'upstream_allow_invalid_certs' will allow upstreams with Invalid/Forged/No TLS certificates to be proxied, be careful.");
    }

    AigisServer::new(AigisServerSettings {
        request_timeout: args.request_timeout,
        proxy_settings: ProxySettings {
            allowed_domains: args.proxy_allowed_domains,
            allowed_mimetypes: args.proxy_allowed_mimetypes,
            max_size: args.proxy_max_size.as_u64(),
            max_content_resize: args.proxy_max_upscale_res,
        },
        upstream_settings: UpstreamSettings {
            allow_invalid_certs: args.upstream_allow_invalid_certs,
            max_redirects: args.upstream_max_redirects,
            pass_headers: args.upstream_pass_headers,
            request_timeout: args.request_timeout,
            use_received_cache_times: args.use_received_cache_times,
        },
    })?
    .start(&args.address)
    .await
}
