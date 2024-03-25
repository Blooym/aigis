//! Crate for Aigis, a simple and configurable content proxy.

#[cfg(feature = "rustls-tls")]
#[cfg(feature = "native-tls")]
compile_error!("You can only enable one TLS backend");

pub extern crate mime;
pub extern crate url;

mod http_client;
mod middleware;
mod mime_util;
mod routes;

use crate::http_client::{build_http_client, BuildHttpClientArgs};
use anyhow::Result;
use axum::{middleware as axum_middleware, routing::get, Router};
use http_client::HttpClient;
use mime::Mime;
use routes::{HEALTH_ENDPOINT, INDEX_ENDPOINT, PROXY_ENDPOINT};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tower_http::{
    catch_panic::CatchPanicLayer,
    normalize_path::NormalizePathLayer,
    timeout::TimeoutLayer,
    trace::{self, TraceLayer},
};
use tracing::{info, Level};
use url::Url;

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
#[derive(Debug, Clone)]
pub struct AigisServer {
    router_inner: Router,
}

/// Settings to run the Aigis server with.
#[derive(Debug, Clone)]
pub struct AigisServerSettings {
    /// How long (in seconds) to allow a request to be processed before it is abandoned
    /// and an error is sent to the client.
    pub request_timeout: u64,
    /// See [`UpstreamSettings`].
    pub upstream_settings: UpstreamSettings,
    /// See [`ProxySettings`].
    pub proxy_settings: ProxySettings,
}

/// Configuration options used for the 'proxy' route.
#[derive(Debug, Clone)]
pub struct ProxySettings {
    /// [`Mime`]s that can be proxied, checked against the Content-Type header
    /// that the upstream server reports.
    ///
    /// Supports type wildcards such as 'image/*'.
    pub allowed_mimetypes: Vec<Mime>,
    /// The maximum Content-Lenth that can be proxied.
    /// Anything larger than this value will not be sent and an error will shown instead.
    pub max_size: u64,
    /// [`Url`]s that can be proxied.
    ///
    /// Does not support subdomain wildcards.
    pub allowed_domains: Option<Vec<Url>>,
    /// The maximum resolution that content that supports resizing can be resized to.
    pub max_content_resize: u32,
}

/// Configuration options used when making any call to an upstream service regardless of route.
#[derive(Debug, Clone)]
pub struct UpstreamSettings {
    /// Headers that will be passed on from the requester to the upstream server verbatim.
    pub pass_headers: Option<Vec<String>>,
    /// Whether or not to allow invalid/expired/forged TLS certificates when making upstream requests.
    ///
    /// Enabling this is dangerous and is usually not necessary.
    pub allow_invalid_certs: bool,
    /// How long (in seconds) to wait for a request to an upstream server to complete before it's abandoned
    /// and an error is sent back to the requester.
    pub request_timeout: u64,
    /// The maximum amount of redirects to follow when making a request to an upstream server before stopping.
    pub max_redirects: usize,
}

impl Default for AigisServerSettings {
    fn default() -> Self {
        Self {
            request_timeout: 10,
            proxy_settings: ProxySettings::default(),
            upstream_settings: UpstreamSettings::default(),
        }
    }
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            allowed_mimetypes: vec![mime::IMAGE_STAR],
            allowed_domains: None,
            max_size: 100000000,
            max_content_resize: 1024,
        }
    }
}

impl Default for UpstreamSettings {
    fn default() -> Self {
        Self {
            allow_invalid_certs: false,
            max_redirects: 10,
            pass_headers: None,
            request_timeout: 30,
        }
    }
}

#[derive(Debug, Clone)]
struct AppState {
    client: HttpClient,
    settings: AigisServerSettings,
}

impl AigisServer {
    /// Create a new [`AigisServer`] using the provided [`AigisServerSettings`].
    pub fn new(settings: AigisServerSettings) -> Result<Self> {
        let router = Router::new()
            .route(PROXY_ENDPOINT, get(routes::proxy_handler))
            .route(INDEX_ENDPOINT, get(routes::index_handler))
            .route(HEALTH_ENDPOINT, get(routes::health_handler))
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
            .layer(axum_middleware::from_fn(middleware::header_middleware))
            .with_state(AppState {
                client: build_http_client(BuildHttpClientArgs {
                    allow_invalid_certs: settings.upstream_settings.allow_invalid_certs,
                    max_redirects: settings.upstream_settings.max_redirects,
                    request_timeout: Duration::from_secs(
                        settings.upstream_settings.request_timeout,
                    ),
                })?,
                settings,
            });

        Ok(Self {
            router_inner: router,
        })
    }

    /// Start the server and expose it on the provided [`SocketAddr`].
    pub async fn start(self, address: &SocketAddr) -> Result<()> {
        let tcp_listener = TcpListener::bind(&address).await?;
        info!("Listening on http://{}", tcp_listener.local_addr()?);
        axum::serve(tcp_listener, self.router_inner)
            .with_graceful_shutdown(async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to listen for ctrl-c");
            })
            .await?;

        Ok(())
    }
}
