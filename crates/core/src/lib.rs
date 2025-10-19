//! Crate for Aigis, a simple and configurable content proxy.

#[cfg(feature = "rustls-tls")]
#[cfg(feature = "native-tls")]
compile_error!("You can only enable one TLS backend");

pub extern crate mime;
pub extern crate url;

mod http_client;
mod mime_util;
mod routes;

use crate::http_client::{BuildHttpClientArgs, build_http_client};
use anyhow::Result;
use axum::{
    Router,
    extract::Request,
    http::HeaderValue,
    middleware::{self as axum_middleware, Next},
    response::Response,
    routing::get,
};
use http_client::HttpClient;
use mime::Mime;
use reqwest::header;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, signal};
use tower_http::{
    catch_panic::CatchPanicLayer,
    normalize_path::NormalizePathLayer,
    timeout::TimeoutLayer,
    trace::{self, TraceLayer},
};
use tracing::{Level, info};
use url::Url;

/// The Aigis server itself.
/// # Example
/// ```rust,no_run
/// use std::net::{SocketAddr, IpAddr, Ipv4Addr};
/// use aigis::{AigisServer, AigisServerSettings};
///
/// # #[tokio::main]
/// # async fn main() {
/// let server = AigisServer::new(AigisServerSettings::default()).unwrap();
/// server.start(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)).await.unwrap();
/// # }
/// ```
#[derive(Debug)]
pub struct AigisServer {
    router_inner: Router,
}

/// Settings to run the Aigis server with.
#[derive(Debug, Clone)]
pub struct AigisServerSettings {
    /// How many seconds that can elapse before a request is abandoned for taking too long.
    pub request_timeout: u64,

    /// See [`UpstreamSettings`].
    pub upstream_settings: UpstreamSettings,

    /// See [`ProxySettings`].
    pub proxy_settings: ProxySettings,
}

/// Configuration options used for the `proxy` route.
#[derive(Debug, Clone)]
pub struct ProxySettings {
    /// [`Mime`]s that are allowed to be proxied, checked against the Content-Type header
    /// received from the upstream server.
    ///
    /// Supports type wildcards such as 'image/*'.
    pub allowed_mimetypes: Vec<Mime>,

    /// The maximum Content-Lenth that can be proxied.
    /// Anything larger than this value will not be sent and an error will shown instead.
    pub max_content_length: u64,

    /// [`Url`]s that are allowed to be proxied.
    ///
    /// Does not support subdomain wildcards, each domain must be added seperately.
    pub allowed_domains: Option<Vec<Url>>,

    /// The maximum resolution that can be requested for content that supports resizing.
    pub max_rescale_resolution: u32,
}

/// Configuration options used when making any call to an upstream service regardless of route.
#[derive(Debug, Clone)]
pub struct UpstreamSettings {
    /// Headers that will be passed on from the client to the upstream server verbatim.
    pub forwarded_headers: Option<Vec<String>>,

    /// Whether to allow invalid/expired/forged TLS certificates when making upstream requests.
    ///
    /// **Enabling this is dangerous and is usually not necessary.**
    pub allow_invalid_certs: bool,

    /// How many seconds that can elapse after sending a request to an upstream server before it's abandoned
    /// and considered failed.
    pub request_timeout: u64,

    /// The maximum amount of redirects to follow when making a request to an upstream server before abandoning the request.
    pub max_redirects: usize,

    /// Whether to send the client the `Cache-Control` header value that was received when making the
    /// request to the upstream server if one is available.
    ///
    /// If one of the `cache-*` crate features are enabled the request will already be cached server-side for that requested duration,
    /// so sending the `Cache-Control` header to the client is favourable behaviour as it can sometimes lighten server load.
    pub use_cache_headers: bool,
}

#[derive(Debug)]
struct AppState {
    client: HttpClient,
    settings: AigisServerSettings,
}

impl AigisServer {
    /// Create a new server with the provided settings.
    pub fn new(settings: AigisServerSettings) -> Result<Self> {
        let router = Router::new()
            .route("/proxy/{url}", get(routes::proxy_handler))
            .route("/", get(routes::index_handler))
            .route("/health", get(routes::health_handler))
            .route("/metadata/{url}", get(routes::metadata_handler))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
            )
            .layer(TimeoutLayer::new(Duration::from_secs(
                settings.request_timeout,
            )))
            .layer(NormalizePathLayer::trim_trailing_slash())
            .layer(CatchPanicLayer::new())
            .layer(axum_middleware::from_fn(AigisServer::header_middleware))
            .with_state(Arc::new(AppState {
                client: build_http_client(BuildHttpClientArgs {
                    allow_invalid_certs: settings.upstream_settings.allow_invalid_certs,
                    max_redirects: settings.upstream_settings.max_redirects,
                    request_timeout: Duration::from_secs(
                        settings.upstream_settings.request_timeout,
                    ),
                })?,
                settings,
            }));

        Ok(Self {
            router_inner: router,
        })
    }

    /// Start the server and expose it locally on the provided [`SocketAddr`].
    pub async fn start(self, address: &SocketAddr) -> Result<()> {
        let tcp_listener = TcpListener::bind(&address).await?;
        info!("Listening on http://{}", tcp_listener.local_addr()?);
        axum::serve(tcp_listener, self.router_inner)
            .with_graceful_shutdown(Self::shutdown_signal())
            .await?;
        Ok(())
    }

    // https://github.com/tokio-rs/axum/blob/15917c6dbcb4a48707a20e9cfd021992a279a662/examples/graceful-shutdown/src/main.rs#L55
    async fn shutdown_signal() {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }

    async fn header_middleware(request: Request, next: Next) -> Response {
        let mut response = next.run(request).await;
        response.headers_mut().append(
            header::SERVER,
            HeaderValue::from_static(env!("CARGO_PKG_NAME")),
        );
        response
            .headers_mut()
            .append("X-Robots-Tag", HeaderValue::from_static("none"));
        response
    }
}
