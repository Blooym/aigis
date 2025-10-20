use aigis::{
    AigisServer, AigisServerSettings, ProxySettings, UpstreamSettings,
    mime::{IMAGE_STAR, Mime},
    url::Url,
};
use anyhow::Result;
use bytesize::ByteSize;
use clap::Parser;
use core::{net::SocketAddr, str::FromStr};
use dotenvy::dotenv;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about)]
struct Arguments {
    /// Internet socket address that the server should be ran on.
    #[arg(
        long = "address",
        env = "AIGIS_ADDRESS",
        default_value = "127.0.0.1:3500"
    )]
    address: SocketAddr,

    /// Maximum waiting time for incoming requests before aborting (in seconds).
    #[arg(
        long = "request-timeout",
        env = "AIGIS_REQUEST_TIMEOUT",
        default_value_t = 15
    )]
    request_timeout: u64,

    /// Maximum waiting time for upstream requests before aborting (in seconds).
    #[arg(
        long = "upstream-request-timeout",
        env = "AIGIS_UPSTREAM_REQUEST_TIMEOUT",
        default_value_t = 10
    )]
    upstream_request_timeout: u64,

    /// Maximum amount of redirects to follow when making upstream requests before aborting.
    #[arg(
        long = "upstream-max-redirects",
        env = "AIGIS_UPSTREAM_MAX_REDIRECTS",
        default_value_t = 5
    )]
    upstream_max_redirects: usize,

    /// A list of header names that should be passed from the original request to the upstream if they are set.
    /// Leave empty to not pass any headers.
    #[arg(
        long = "upstream-forwarded-headers",
        env = "AIGIS_UPSTREAM_FORWARDED_HEADERS",
        value_delimiter = ','
    )]
    upstream_forwarded_headers: Option<Vec<String>>,

    /// DANGEROUS: Allow self-signed/invalid/forged TLS certificates when making upstream requests.
    #[arg(
        long = "upstream-allow-invalid-certs",
        env = "AIGIS_UPSTREAM_ALLOW_INVALID_CERTS",
        default_value_t = false
    )]
    upstream_allow_invalid_certs: bool,

    /// Whether to send the `Cache-Control` header value that was received from the
    /// upstream server along with the proxied response.
    ///
    /// If one of the `cache-*` crate features are enabled the request will already be cached locally for the requested duration,
    /// so sending the `Cache-Control` header to the client is favourable behaviour as it can sometimes lighten server load.
    #[arg(
        long = "upstream-use-cache-headers",
        env = "AIGIS_UPSTREAM_USE_CACHE_HEADERS",
        default_value_t = true
    )]
    upstream_use_cache_headers: std::primitive::bool,

    /// Maximum Content-Length that can be proxied by this server.
    ///
    /// Note: this is currently not a well-rounded check and relies on the server
    /// sending an honest header. This may be improved in the future.
    #[arg(
        long = "proxy-max-content-length",
        env = "AIGIS_PROXY_MAX_CONTENT_LENGTH",
        default_value = "50MB"
    )]
    proxy_max_content_length: ByteSize,

    /// A list of MIME "essence" strings that are allowed to be proxied by this server.
    /// Supports type wildcards (e.g. 'image/*').
    #[arg(
        long = "proxy-allowed-mimetypes",
        env = "AIGIS_PROXY_ALLOWED_MIMETYPES",
        default_values_t = [
            IMAGE_STAR,
            Mime::from_str("video/*").unwrap()
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

    AigisServer::new(AigisServerSettings {
        request_timeout: args.request_timeout,
        request_proxy: None,
        use_request_cache: true,
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
            request_timeout: args.request_timeout,
            use_cache_headers: args.upstream_use_cache_headers,
        },
    })?
    .start(&args.address)
    .await
}
