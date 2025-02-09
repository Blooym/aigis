use crate::{mime_util, AppState};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use image::{imageops::FilterType, ImageFormat, ImageReader};
use mime::*;
use serde::{Deserialize, Serialize};
use std::{
    io::{BufReader, BufWriter, Cursor},
    str::FromStr,
};
use tracing::{debug, warn};
use url::Url;

pub const PROXY_ENDPOINT: &str = "/proxy/{url}";

#[derive(Debug, Deserialize)]
pub struct ProxyRequestQueryParams {
    /// The content format to return after proxying.
    /// If the content does not have support implemented for format adjustments
    /// then this field will be ignored.
    pub format: Option<String>,

    /// The content size to return after proxying (with aspect ratio maintained).
    /// If the content does not have implemented support size adjustments
    /// then this field will be ignored.
    pub size: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ProxyError<'a> {
    message: &'a str,
}

pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(url): Path<Url>,
    headers: HeaderMap,
    query: Query<ProxyRequestQueryParams>,
) -> Response {
    // If allowed_domains is enabled, check if this domain is allowed.
    if let Some(allowed_domains) = state.settings.proxy_settings.allowed_domains {
        if !allowed_domains.contains(&url) {
            return (
                StatusCode::BAD_REQUEST,
                Json(ProxyError {
                    message: "Proxying for this domain is not permitted.",
                }),
            )
                .into_response();
        }
    }

    // Make a request to the upstream, passing any headers that have been configured.
    let mut request = state.client.get(url);
    if let Some(pass_headers) = state.settings.upstream_settings.pass_headers {
        for pass_header in pass_headers {
            if let Some(header_value) = headers.get(&pass_header) {
                if let Ok(header_value_str) = header_value.to_str() {
                    debug!("Attaching header {pass_header} to upstream request");
                    request = request.header(pass_header, header_value_str);
                }
            }
        }
    }
    let upstream_response = match request.send().await {
        Err(err) => {
            warn!("Failed to make request to upstream server: {}", err);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ProxyError {
                    message: "Failed to send request to upstream server.",
                }),
            )
                .into_response();
        }
        Ok(data) => {
            if let Err(err) = data.error_for_status_ref() {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(ProxyError {
                        message: format!(
                            "Upstream server responded with a unsuccessful status code: {}",
                            err
                        )
                        .as_str(),
                    }),
                )
                    .into_response();
            }
            data
        }
    };

    // Make sure a valid Content-Type was received and that it's allowed to be proxied by this server.
    let Some(mut content_type) = upstream_response
        .headers()
        .get(header::CONTENT_TYPE.to_string())
        .map(|s| s.to_str().unwrap().parse().unwrap())
    else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(ProxyError {
                message:
                    "Upstream server either did not send or sent an invalid Content-Type header.",
            }),
        )
            .into_response();
    };
    if !mime_util::is_mime_allowed(
        &content_type,
        &state.settings.proxy_settings.allowed_mimetypes,
    ) {
        return (StatusCode::BAD_REQUEST, format!(
            "Refusing to proxy the request content as proxying for '{}' is not enabled on this server.",
            content_type.essence_str()
        )).into_response();
    }

    // Ensure that the Content-Length header value is below the servers max size.
    let Some(content_length) = upstream_response.content_length() else {
        return (
            StatusCode::BAD_GATEWAY,
            "Upstream did not provide Content-Length information.",
        )
            .into_response();
    };
    if content_length > state.settings.proxy_settings.max_size {
        return (
            StatusCode::BAD_REQUEST,
            "Refusing to proxy requested content as it exceeds the maximum Content-Length.",
        )
            .into_response();
    }

    // Get the cache control header sent to us if one is available.
    let cache_control_header = upstream_response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .map(|h| HeaderValue::from_str(h.to_str().unwrap()).unwrap());

    // Ensure that the response contains a response body.
    let Ok(mut req_body_bytes) = upstream_response.bytes().await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong whilst obtaining the request body from upstream.",
        )
            .into_response();
    };

    // If the provided Content-Type is an image and the query requested
    // image changes, apply them.
    if content_type.type_() == mime::IMAGE && (query.0.size.is_some()) || query.0.format.is_some() {
        let Some(mime_image_type) = ImageFormat::from_mime_type(content_type.essence_str()) else {
            return (
                StatusCode::BAD_REQUEST,
                "Image modifications were requested on an unsupported content format.",
            )
                .into_response();
        };
        let image_format = query
            .0
            .format
            .map(|s| ImageFormat::from_extension(s).unwrap_or(mime_image_type))
            .unwrap_or(mime_image_type);

        // Decode image
        let Ok(mut image) =
            ImageReader::with_format(BufReader::new(Cursor::new(req_body_bytes)), mime_image_type)
                .decode()
        else {
            return (
                StatusCode::BAD_REQUEST,
                "Unable to decode image receieved from upstream server.",
            )
                .into_response();
        };

        let mut buffer: Vec<u8> = Vec::new();

        // Conditionally apply resizing if requested.
        if let Some(resize) = query.0.size {
            debug!("Applying resize to requested image");
            if resize > state.settings.proxy_settings.max_content_rescale_resolution {
                return (
                    StatusCode::BAD_REQUEST,
                    "The requested image size was too large to be processed by this server.",
                )
                    .into_response();
            }
            image = image.resize(resize, resize, FilterType::Nearest);
        }

        // Write image using either the original or requested image format
        // then overwrite the request body and content_type values.
        if image
            .write_to(&mut BufWriter::new(Cursor::new(&mut buffer)), image_format)
            .is_err()
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An error occured whilst attempting to process image modifications.",
            )
                .into_response();
        };

        req_body_bytes = Bytes::from_iter(buffer);
        content_type = Mime::from_str(image_format.to_mime_type())
            .expect("image format mime type should be a valid format");
    }

    let mut response = Response::new(Body::from(req_body_bytes));
    response.headers_mut().append(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type.essence_str()).unwrap(),
    );

    // Make cleaner sometime: https://github.com/rust-lang/rust/issues/53667
    if state.settings.upstream_settings.use_received_cache_headers {
        if let Some(cache_control_header) = cache_control_header {
            response
                .headers_mut()
                .append(header::CACHE_CONTROL, cache_control_header);
        }
    }

    response
}
