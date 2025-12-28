//! Crate for Aigis, a simple and configurable content proxy.

#[cfg(feature = "rustls-tls")]
#[cfg(feature = "native-tls")]
compile_error!("You can only enable one TLS backend");

mod cache;
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
use cache::{Cache, build_response_cache};
use core::{net::SocketAddr, time::Duration};
use http_client::{BuildHttpClientArgs, HttpClient, build_http_client};
use mime::Mime;
use reqwest::{Proxy, StatusCode, header};
use std::sync::Arc;
use tokio::{net::TcpListener, signal};
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::CompressionLayer,
    normalize_path::NormalizePathLayer,
    timeout::TimeoutLayer,
    trace::{self, TraceLayer},
};
use tracing::{Level, info};
use url::Url;

pub struct Server {
    router: Router,
}

pub struct Settings {
    pub request_timeout: Duration,
    pub upstream_settings: UpstreamSettings,
    pub proxy_settings: ProxySettings,
    pub cache_settings: CacheSettings,
}

pub struct ProxySettings {
    pub allowed_mimetypes: Box<[Mime]>,
    pub max_content_length: u64,
    pub allowed_domains: Option<Box<[Url]>>,
    pub max_rescale_resolution: u32,
}

pub struct CacheSettings {
    pub max_size: u64,
    pub time_to_idle: Option<Duration>,
}
pub struct UpstreamSettings {
    pub forwarded_headers: Option<Box<[String]>>,
    pub allow_invalid_certs: bool,
    pub request_timeout: Duration,
    pub max_redirects: usize,
    pub request_proxy: Option<Url>,
}

struct AppState {
    http_client: HttpClient,
    response_cache: Cache,
    server_settings: Settings,
}

impl Server {
    /// Create a new server with the provided settings.
    pub fn new(settings: Settings) -> Result<Self> {
        let router = Router::new()
            .route("/", get(routes::index_handler))
            .route("/health", get(routes::health_handler))
            .route("/metadata/{url}", get(routes::metadata_handler))
            .route("/proxy/{url}", get(routes::proxy_handler))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_request(trace::DefaultOnRequest::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
            )
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                settings.request_timeout,
            ))
            .layer(NormalizePathLayer::trim_trailing_slash())
            .layer(CatchPanicLayer::new())
            .layer(CompressionLayer::new())
            .layer(axum_middleware::from_fn(Self::header_middleware))
            .with_state(Arc::new(AppState {
                http_client: build_http_client(BuildHttpClientArgs {
                    allow_invalid_certs: settings.upstream_settings.allow_invalid_certs,
                    max_redirects: settings.upstream_settings.max_redirects,
                    request_timeout: settings.upstream_settings.request_timeout,
                    proxy: settings
                        .upstream_settings
                        .request_proxy
                        .as_ref()
                        .map(|p| Proxy::all(p.as_str()))
                        .transpose()?,
                })?,
                response_cache: build_response_cache(
                    settings.cache_settings.max_size,
                    settings.cache_settings.time_to_idle,
                ),
                server_settings: settings,
            }));

        Ok(Self { router })
    }

    /// Start the server and expose it locally on the provided [`SocketAddr`].
    pub async fn start(self, address: &SocketAddr) -> Result<()> {
        let tcp_listener = TcpListener::bind(&address).await?;
        info!("Listening on http://{}", tcp_listener.local_addr()?);
        axum::serve(tcp_listener, self.router)
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
