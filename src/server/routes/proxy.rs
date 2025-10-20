use crate::server::{AppState, mime_util};
use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use bytes::Bytes;
use image::{ImageFormat, ImageReader, imageops::FilterType};
use infer::MatcherType;
use mime::{APPLICATION_OCTET_STREAM, Mime};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
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
    #[serde(rename = "lowercase")]
    pub format: Option<ImageFormat>,

    /// The content size to return (with aspect ratio maintained).
    ///
    /// If the content does support size adjustments.
    /// or an invalid option for the content is used, this will be ignored.
    pub size: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ProxyError {
    message: Cow<'static, str>,
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
                message: Cow::Borrowed("Invalid URL: no host found."),
            }),
        ))?;
        if !allowed_domains
            .iter()
            .any(|allowed| allowed.host_str() == Some(domain))
        {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ProxyError {
                    message: Cow::Borrowed("Proxying for this domain is not permitted."),
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
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        Json(ProxyError {
                            message: Cow::Owned(format!(
                                "Upstream server responded with an unsuccessful status code: {}",
                                err
                            )),
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
                            message: Cow::Borrowed("Upstream server failed to respond in time."),
                        }),
                    ));
                }
                if err.is_redirect() {
                    return Err((
                        StatusCode::BAD_GATEWAY,
                        Json(ProxyError {
                            message: Cow::Borrowed("Upstream server redirected too many times."),
                        }),
                    ));
                }
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ProxyError {
                        message: Cow::Borrowed("Failed to send request to upstream server."),
                    }),
                ));
            }
        }
    };

    // Ensure that the Content-Length header value is below the servers max size.
    //
    // NOTE: This does not guarentee that the content is the size it reports,
    // so further analysis should be done when downloading the body via a stream.
    if let Some(content_length) = upstream_response.content_length() {
        if content_length > state.settings.proxy_settings.max_content_length {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ProxyError {
                    message: Cow::Borrowed(
                        "Refusing to proxy requested content as it exceeds the maximum size.",
                    ),
                }),
            ));
        }
    } else {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(ProxyError {
                message: Cow::Borrowed("Unable to resolve content length of requested content."),
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
                    message: Cow::Owned(format!(
                        "Refusing to proxy the request content as proxying for '{}' is not enabled on this server.",
                        content_type.essence_str()
                    )),
                }),
            ));
        }
    } else {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(ProxyError {
                message: Cow::Borrowed(
                    "Upstream server sent a missing or invalid Content-Type header.",
                ),
            }),
        ));
    };

    // Get the cache control header sent to us if one is available.
    let cache_control_header = upstream_response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    // Download content.
    let Ok(mut req_body_bytes) = upstream_response.bytes().await else {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(ProxyError {
                message: Cow::Borrowed(
                    "Something went wrong whilst obtaining the content from upstream.",
                ),
            }),
        ));
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
                        message: Cow::Owned(format!(
                            "Refusing to proxy content as proxying for '{}' is not enabled on this server.",
                            inferred_mime.essence_str()
                        )),
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
                        message: Cow::Borrowed(
                            "Unable to determine the MIME type of the upstream content.",
                        ),
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
                        message: Cow::Borrowed(
                            "Image modifications were requested on an unsupported content format.",
                        ),
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
                        message: Cow::Borrowed(
                            "Unable to decode image received from upstream server.",
                        ),
                    }),
                )
            })?;

            // Conditionally apply resizing if requested.
            if let Some(resize) = query.0.size {
                if resize > state.settings.proxy_settings.max_rescale_resolution {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(ProxyError {
                            message: Cow::Borrowed(
                                "The requested image size was too large to be processed by this server.",
                            ),
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
                        message: Cow::Borrowed(
                            "An error occurred whilst attempting to process image modifications.",
                        ),
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
    if let Some(cache_control_header) = cache_control_header
        && state.settings.upstream_settings.use_cache_headers
    {
        response
            .headers_mut()
            .append(header::CACHE_CONTROL, cache_control_header);
    }
    Ok(response)
}
