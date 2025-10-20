//! Crate for Aigis, a simple and configurable content proxy.

#[cfg(feature = "rustls-tls")]
#[cfg(feature = "native-tls")]
compile_error!("You can only enable one TLS backend");

mod http_client;
mod mime_util;
mod routes;

use anyhow::Result;
use axum::{
    Router,
    extract::Request,
    http::HeaderValue,
    middleware::{self as axum_middleware, Next},
    response::Response,
    routing::get,
};
use core::{net::SocketAddr, time::Duration};
use http_client::{BuildHttpClientArgs, HttpClient, build_http_client};
use mime::Mime;
use reqwest::{Proxy, header};
use std::sync::Arc;
use tokio::{net::TcpListener, signal};
use tower_http::{
    catch_panic::CatchPanicLayer,
    normalize_path::NormalizePathLayer,
    timeout::TimeoutLayer,
    trace::{self, TraceLayer},
};
use tracing::{Level, info};
use url::Url;

#[derive(Debug)]
pub struct AigisServer {
    router_inner: Router,
}

/// Settings to run the Aigis server with.
#[derive(Debug, Clone)]
pub struct AigisServerSettings {
    /// How many seconds that can elapse before a request is abandoned for taking too long.
    pub request_timeout: u64,

    /// The Socks5 proxy to use for all outgoing requests.
    pub request_proxy: Option<Url>,

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
    pub allowed_mimetypes: Box<[Mime]>,

    /// The maximum Content-Lenth that can be proxied.
    /// Anything larger than this value will not be sent and an error will shown instead.
    pub max_content_length: u64,

    /// [`Url`]s that are allowed to be proxied.
    ///
    /// Does not support subdomain wildcards, each domain must be added seperately.
    pub allowed_domains: Option<Box<[Url]>>,

    /// The maximum resolution that can be requested for content that supports resizing.
    pub max_rescale_resolution: u32,
}

/// Configuration options used when making any call to an upstream service regardless of route.
#[derive(Debug, Clone)]
pub struct UpstreamSettings {
    /// Headers that will be passed on from the client to the upstream server verbatim.
    pub forwarded_headers: Option<Box<[String]>>,

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
            .route("/", get(routes::index_handler))
            .route("/health", get(routes::health_handler))
            .route("/metadata/{url}", get(routes::metadata_handler))
            .route("/proxy/{url}", get(routes::proxy_handler))
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
                    proxy: settings
                        .request_proxy
                        .as_ref()
                        .map(|p| Proxy::all(p.as_str()))
                        .transpose()?,
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
