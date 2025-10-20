use crate::server::{AppState, mime_util};
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use futures::StreamExt;
use image::{ImageFormat, ImageReader, imageops::FilterType};
use infer::MatcherType;
use mime::{APPLICATION_OCTET_STREAM, Mime};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufReader, BufWriter, Cursor},
    str::FromStr,
    sync::Arc,
};
use tracing::{debug, warn};
use url::Url;

#[derive(Deserialize)]
pub struct ProxyRequestQueryParams {
    /// The format of the content to use.
    ///
    /// If the content does support format adjustments.
    /// or an invalid option for the content is used, this will be ignored.
    pub format: Option<ImageFormat>,

    /// The content size to return (with aspect ratio maintained).
    ///
    /// If the content does support size adjustments.
    /// or an invalid option for the content is used, this will be ignored.
    pub size: Option<u32>,
}

#[derive(Serialize)]
pub struct ProxyError {
    message: &'static str,
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path(url): Path<Url>,
    headers: HeaderMap,
    query: Query<ProxyRequestQueryParams>,
) -> Result<Response, (StatusCode, Json<ProxyError>)> {
    // If allowed_domains is set, check if this domain is included.
    if let Some(allowed_domains) = &state.settings.proxy_settings.allowed_domains {
        let domain = url.host_str().ok_or((
            StatusCode::BAD_REQUEST,
            Json(ProxyError {
                message: "Invalid URL: no host found.",
            }),
        ))?;
        if !allowed_domains
            .iter()
            .any(|allowed| allowed.host_str() == Some(domain))
        {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ProxyError {
                    message: "Proxying for this domain is not permitted.",
                }),
            ));
        }
    }

    // Make a request to the upstream, passing any headers that have been configured.
    let upstream_response = {
        let mut request = state.client.get(url);
        if let Some(forwarded_headers) = &state.settings.upstream_settings.forwarded_headers {
            for pass_header in forwarded_headers {
                if let Some(header_value) = headers.get(pass_header).and_then(|v| v.to_str().ok()) {
                    debug!("Attaching header {pass_header} to upstream request");
                    request = request.header(pass_header, header_value);
                }
            }
        }
        match request.send().await {
            Ok(data) => {
                if let Err(err) = data.error_for_status_ref() {
                    warn!("Upstream returned unsuccessful status code {err:?}");
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        Json(ProxyError {
                            message: "Unable to retrieve content from upstream server.",
                        }),
                    ));
                }
                data
            }
            Err(err) => {
                warn!("Failed to make request to upstream server: {}", err);
                if err.is_timeout() {
                    return Err((
                        StatusCode::GATEWAY_TIMEOUT,
                        Json(ProxyError {
                            message: "Upstream server failed to respond in time.",
                        }),
                    ));
                }
                if err.is_redirect() {
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        Json(ProxyError {
                            message: "Upstream server redirected too many times.",
                        }),
                    ));
                }
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ProxyError {
                        message: "Failed to send request to upstream server.",
                    }),
                ));
            }
        }
    };

    if let Some(content_length) = upstream_response.content_length()
        && content_length > state.settings.proxy_settings.max_content_length
    {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ProxyError {
                message: "Refusing to proxy requested content as it exceeds the maximum size.",
            }),
        ));
    };

    // Make sure a valid Content-Type was received and that it's allowed to be proxied by this server.
    //
    // Note: This is only the first check for the Content-Type, as the real Content-Type will be inferred
    // via reading the buffer itself. This is just a first-case to fail early to prevent needing to download
    // the content itself if it can be avoided.
    if let Some(content_type) = upstream_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
    {
        if !mime_util::is_mime_allowed(
            &content_type,
            &state.settings.proxy_settings.allowed_mimetypes,
        ) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ProxyError {
                    message: "Refusing to proxy content as proxying the content type is not enabled on this server.",
                }),
            ));
        }
    } else {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(ProxyError {
                message: "Upstream server sent a missing or invalid Content-Type header.",
            }),
        ));
    };

    // Get the cache control header sent to us if one is available.
    let headers = upstream_response.headers().clone();
    let mut req_body_bytes = {
        let mut stream = upstream_response.bytes_stream();
        let mut buffer = vec![];
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|_| {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(ProxyError {
                        message: "Something went wrong whilst obtaining the content from upstream.",
                    }),
                )
            })?;
            if buffer.len() as u64 + chunk.len() as u64
                > state.settings.proxy_settings.max_content_length
            {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(ProxyError {
                        message: "Content exceeded maximum allowed size.",
                    }),
                ));
            }
            buffer.extend_from_slice(&chunk);
        }
        Bytes::from(buffer)
    };

    // Infer mimetype by magic numbers.
    // (Octet stream is used as fallback when */* is allowed, otherwise unknown types are rejected.)
    let (mut content_type, matcher_type) = match infer::get(&req_body_bytes) {
        Some(infer_result) => {
            let inferred_mime = Mime::from_str(infer_result.mime_type())
                .expect("infer crate should return valid MIME types");

            // Check if the inferred MIME type is allowed
            if !mime_util::is_mime_allowed(
                &inferred_mime,
                &state.settings.proxy_settings.allowed_mimetypes,
            ) {
                // Reject as unsupported type.
                debug!(
                    "Rejecting proxy request - server does not allow MIME type: {}",
                    inferred_mime.essence_str()
                );
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ProxyError {
                        message: "Refusing to proxy content as proxying the content type is not enabled on this server.",
                    }),
                ));
            }

            (inferred_mime, infer_result.matcher_type())
        }
        None => {
            // If no MIME type could be inferred, check if fallback is allowed.
            if state
                .settings
                .proxy_settings
                .allowed_mimetypes
                .contains(&mime::STAR_STAR)
            {
                // Fallback to octet stream
                debug!(
                    "Could not infer content MIME type - falling back to application/octet-stream"
                );
                (APPLICATION_OCTET_STREAM, MatcherType::Archive)
            } else {
                // Reject as unsupported type.
                debug!("Rejecting proxy request - No MIME type could be inferred from content");
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ProxyError {
                        message: "Unable to determine the MIME type of the upstream content.",
                    }),
                ));
            }
        }
    };

    // If the provided Content-Type is an image and the query requested
    // image changes, apply them.
    match matcher_type {
        MatcherType::Image if query.0.size.is_some() || query.0.format.is_some() => {
            let Some(image_format) = ImageFormat::from_mime_type(content_type) else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ProxyError {
                        message: "Image modifications were requested on an unsupported content format.",
                    }),
                ));
            };
            let mut image = ImageReader::with_format(
                BufReader::new(Cursor::new(&req_body_bytes)),
                image_format,
            )
            .decode()
            .map_err(|_| {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(ProxyError {
                        message: "Unable to decode image received from upstream server.",
                    }),
                )
            })?;

            // Conditionally apply resizing if requested.
            if let Some(resize) = query.0.size {
                if resize > state.settings.proxy_settings.max_rescale_resolution {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(ProxyError {
                            message: "The requested image size was too large to be processed by this server.",
                        }),
                    ));
                }
                image = image.resize(resize, resize, FilterType::Nearest);
                debug!("Resized image to {}x{}", image.width(), image.height());
            }

            // Write image using either the original or requested image format
            // then overwrite the request body and content_type values.
            let original_size = req_body_bytes.len();
            let output_format = query.0.format.unwrap_or(image_format);
            let mut buffer = Vec::with_capacity(original_size);
            image
            .write_to(&mut BufWriter::new(Cursor::new(&mut buffer)), output_format)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ProxyError {
                        message:"An error occurred whilst attempting to process image modifications.",
                    }),
                )
            })?;

            debug!(
                "Processed image (original: {} bytes, processed: {} bytes)",
                original_size,
                buffer.len()
            );
            req_body_bytes = Bytes::from(buffer);
            content_type = Mime::from_str(output_format.to_mime_type())
                .expect("image format mime type should be a valid format");
        }
        _ => {}
    };

    let mut response = Response::new(Body::from(req_body_bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type.essence_str()).unwrap(),
    );

    if state.settings.upstream_settings.use_cache_headers {
        if let Some(cache_control_header) = headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
        {
            response
                .headers_mut()
                .append(header::CACHE_CONTROL, cache_control_header);
        }
        if let Some(age_header) = headers
            .get(header::AGE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
        {
            response.headers_mut().append(header::AGE, age_header);
        }
        if let Some(etag_header) = headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
        {
            response.headers_mut().append(header::ETAG, etag_header);
        }
    }

    Ok(response)
}
