use crate::server::{
    AppState,
    cache::{CacheSize, CachedResponse},
    mime_util,
    routes::{AIGIS_CACHE_HEADER, AIGIS_CACHE_HEADER_VALUE_HIT, ErrorResponse},
};
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use futures::StreamExt;
use http_cache_semantics::CachePolicy;
use image::{ImageFormat, ImageReader, imageops::FilterType};
use infer::MatcherType;
use mime::{APPLICATION_OCTET_STREAM, Mime};
use serde::Deserialize;
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    io::{BufReader, BufWriter, Cursor},
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};
use tracing::{debug, warn};
use url::Url;

#[derive(Deserialize, Hash)]
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

#[derive(Clone)]
pub struct ProxyResponseWrapper {
    pub body: Bytes,
    pub headers: HeaderMap,
    pub cache_policy: Arc<CachePolicy>,
}

impl CacheSize for ProxyResponseWrapper {
    fn cache_size_shallow(&self) -> usize {
        std::mem::size_of::<Self>() + self.body.len() + self.headers.capacity()
    }
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path(url): Path<Url>,
    request_headers: HeaderMap,
    request_query: Query<ProxyRequestQueryParams>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let cache_key = {
        let mut hasher = DefaultHasher::new();
        hasher.write(b"proxy");
        url.hash(&mut hasher);
        request_query.hash(&mut hasher);
        if let Some(forwarded_headers) = &state.server_settings.upstream_settings.forwarded_headers
        {
            for header_name in forwarded_headers {
                if let Some(header_value) = request_headers
                    .get(header_name.as_str())
                    .and_then(|v| v.to_str().ok())
                {
                    header_name.hash(&mut hasher);
                    header_value.hash(&mut hasher);
                }
            }
        }
        hasher.finish()
    };

    let (response_wrapper, cache_hit) = match state.response_cache.get(&cache_key).await {
        Some((CachedResponse::Proxy(response_wrapper), _))
            if !response_wrapper.cache_policy.is_stale(SystemTime::now()) =>
        {
            // Check if conditional request and handle accordingly.
            if request_headers
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .map(|etag| etag == cache_key.to_string())
                .unwrap_or(false)
            {
                // Return 304 Not Modified
                let mut response = Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Body::empty())
                    .unwrap();
                response.headers_mut().extend(response_wrapper.headers);
                response.headers_mut().insert(
                    header::AGE,
                    response_wrapper
                        .cache_policy
                        .age(SystemTime::now())
                        .as_secs()
                        .into(),
                );
                response
                    .headers_mut()
                    .insert(AIGIS_CACHE_HEADER, AIGIS_CACHE_HEADER_VALUE_HIT);
                return Ok(response);
            }
            // Non-conditional, proceed as regular cached request.
            (response_wrapper, true)
        }
        _ => {
            // If allowed_domains is set, check if this domain is included.
            if let Some(allowed_domains) = &state.server_settings.proxy_settings.allowed_domains {
                let domain = url.host_str().ok_or((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        message: "Invalid URL: no host found.",
                    }),
                ))?;
                if !allowed_domains
                    .iter()
                    .any(|allowed| allowed.host_str() == Some(domain))
                {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            message: "Proxying for this domain is not permitted.",
                        }),
                    ));
                }
            }

            // Make a request to the upstream, passing any headers that have been configured.
            let (response, cache_policy) = {
                let mut request_builder = state.http_client.get(url.as_str());
                if let Some(forwarded_headers) =
                    &state.server_settings.upstream_settings.forwarded_headers
                {
                    for header_name in forwarded_headers {
                        if let Some(header_value) = request_headers
                            .get(header_name)
                            .and_then(|v| v.to_str().ok())
                        {
                            debug!("Attaching header {header_name} to upstream request");
                            request_builder = request_builder.header(header_name, header_value);
                        }
                    }
                }
                let request_builder = request_builder
                    .build()
                    .expect("request builder should always build a valid request");
                match state
                    .http_client
                    .execute(
                        request_builder
                            .try_clone()
                            .expect("clone of request should not fail"),
                    )
                    .await
                {
                    Ok(response) => {
                        if let Err(err) = response.error_for_status_ref() {
                            warn!("Upstream returned unsuccessful status code {err:?}");
                            return Err((
                                StatusCode::BAD_GATEWAY,
                                Json(ErrorResponse {
                                    message: "Unable to retrieve content from upstream server.",
                                }),
                            ));
                        }
                        let cache = CachePolicy::new(&request_builder, &response);
                        (response, cache)
                    }
                    Err(err) => {
                        warn!("Failed to make request to upstream server: {err:?}");
                        if err.is_timeout() {
                            return Err((
                                StatusCode::GATEWAY_TIMEOUT,
                                Json(ErrorResponse {
                                    message: "Upstream server failed to respond in time.",
                                }),
                            ));
                        }
                        if err.is_redirect() {
                            return Err((
                                StatusCode::BAD_GATEWAY,
                                Json(ErrorResponse {
                                    message: "Upstream server redirected too many times.",
                                }),
                            ));
                        }
                        return Err((
                            StatusCode::BAD_GATEWAY,
                            Json(ErrorResponse {
                                message: "Failed to send request to upstream server.",
                            }),
                        ));
                    }
                }
            };
            let response_headers = response.headers().clone();

            // Validate the size of the body making a guess based the inferred size.
            // This is strictly re-validated later when downloading the actual content.
            if let Some(content_length) = response.content_length()
                && content_length > state.server_settings.proxy_settings.max_content_length
            {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(ErrorResponse {
                        message: "Refusing to proxy requested content as it exceeds the maximum size.",
                    }),
                ));
            };

            // Make sure a valid Content-Type was received and that it's allowed to be proxied by this server.
            //
            // Note: This is only the first check for the Content-Type, as the real Content-Type will be inferred
            // via reading the buffer itself. This is just a first-case to fail early to prevent needing to download
            // the content itself if it can be avoided.
            if let Some(content_type) = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()?.parse().ok())
            {
                if !mime_util::is_mime_allowed(
                    &content_type,
                    &state.server_settings.proxy_settings.allowed_mimetypes,
                ) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            message: "Refusing to proxy content as proxying the content type is not enabled on this server.",
                        }),
                    ));
                }
            } else {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        message: "Upstream server sent a missing or invalid Content-Type header.",
                    }),
                ));
            };

            // Fetch the response's body and abort if it goes over the maximum allowed size.
            let mut response_body = {
                let mut buffer = Vec::with_capacity(
                    response
                        .content_length()
                        .map(|len| {
                            len.min(state.server_settings.proxy_settings.max_content_length)
                                as usize
                        })
                        .unwrap_or_default(),
                );
                let mut stream = response.bytes_stream();
                while let Some(chunk_result) = stream.next().await {
                    let chunk = chunk_result.map_err(|_| {
                        (
                            StatusCode::BAD_GATEWAY,
                            Json(ErrorResponse {
                                message: "Something went wrong whilst obtaining the content from upstream.",
                            }),
                        )
                    })?;
                    if buffer.len() as u64 + chunk.len() as u64
                        > state.server_settings.proxy_settings.max_content_length
                    {
                        return Err((
                            StatusCode::PAYLOAD_TOO_LARGE,
                            Json(ErrorResponse {
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
            let (mut content_type, matcher_type) = match infer::get(&response_body) {
                Some(infer_result) => {
                    let inferred_mime = Mime::from_str(infer_result.mime_type())
                        .expect("infer crate should return valid MIME types");

                    // Check if the inferred MIME type is allowed
                    if !mime_util::is_mime_allowed(
                        &inferred_mime,
                        &state.server_settings.proxy_settings.allowed_mimetypes,
                    ) {
                        // Reject as unsupported type.
                        debug!(
                            "Rejecting proxy request - server does not allow MIME type: {}",
                            inferred_mime.essence_str()
                        );
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(ErrorResponse {
                                message: "Refusing to proxy content as proxying the content type is not enabled on this server.",
                            }),
                        ));
                    }

                    (inferred_mime, infer_result.matcher_type())
                }
                None => {
                    // If no MIME type could be inferred, check if fallback is allowed.
                    if state
                        .server_settings
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
                        debug!(
                            "Rejecting proxy request - No MIME type could be inferred from content"
                        );
                        return Err((
                            StatusCode::BAD_GATEWAY,
                            Json(ErrorResponse {
                                message: "Unable to determine the MIME type of the upstream content.",
                            }),
                        ));
                    }
                }
            };

            // If the provided Content-Type is an image and the query requested
            // image changes, apply them.
            match matcher_type {
                MatcherType::Image
                    if request_query.0.size.is_some() || request_query.0.format.is_some() =>
                {
                    let Some(image_format) = ImageFormat::from_mime_type(content_type) else {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                message: "Image modifications were requested on an unsupported content format.",
                            }),
                        ));
                    };
                    let mut image = ImageReader::with_format(
                        BufReader::new(Cursor::new(&response_body)),
                        image_format,
                    )
                    .decode()
                    .map_err(|_| {
                        (
                            StatusCode::BAD_GATEWAY,
                            Json(ErrorResponse {
                                message: "Unable to decode image received from upstream server.",
                            }),
                        )
                    })?;

                    // Conditionally apply resizing if requested.
                    if let Some(resize) = request_query.0.size {
                        if resize > state.server_settings.proxy_settings.max_rescale_resolution {
                            return Err((
                                StatusCode::BAD_REQUEST,
                                Json(ErrorResponse {
                                    message: "The requested image size was too large to be processed by this server.",
                                }),
                            ));
                        }
                        image = image.resize(resize, resize, FilterType::Nearest);
                        debug!("Resized image to {}x{}", image.width(), image.height());
                    }

                    // Write image using either the original or requested image format
                    // then overwrite the request body and content_type values.
                    let original_size = response_body.len();
                    let output_format = request_query.0.format.unwrap_or(image_format);
                    let mut buffer = Vec::with_capacity(original_size);
                    image
                        .write_to(&mut BufWriter::new(Cursor::new(&mut buffer)), output_format)
                        .map_err(|_| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ErrorResponse {
                                    message:"An error occurred whilst attempting to process image modifications.",
                                }),
                            )
                        })?;

                    debug!(
                        "Processed image (original: {} bytes, processed: {} bytes)",
                        original_size,
                        buffer.len()
                    );
                    response_body = Bytes::from(buffer);
                    content_type = Mime::from_str(output_format.to_mime_type())
                        .expect("image format mime type should be a valid format");
                }
                _ => {}
            };

            // Store specific headers for re-sending from cache.
            let mut response_headers_to_cache = HeaderMap::new();
            response_headers_to_cache.insert(header::ETAG, cache_key.into());
            response_headers_to_cache.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(content_type.essence_str())
                    .expect("header value from mime essence string should always be valid"),
            );
            if let Some(cache_control_header) = response_headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()?.parse().ok())
            {
                response_headers_to_cache.insert(header::CACHE_CONTROL, cache_control_header);
            }

            // Wrap important values and cache the response if allowed.
            let wrapper = ProxyResponseWrapper {
                body: response_body,
                headers: response_headers_to_cache,
                cache_policy: Arc::new(cache_policy),
            };
            if wrapper.cache_policy.is_storable() {
                state
                    .response_cache
                    .insert(
                        cache_key,
                        (
                            CachedResponse::Proxy(wrapper.clone()),
                            wrapper.cache_policy.time_to_live(SystemTime::now()),
                        ),
                    )
                    .await;
            }
            (wrapper, false)
        }
    };

    let mut response = Response::new(Body::from(response_wrapper.body));
    response.headers_mut().extend(response_wrapper.headers);
    response.headers_mut().insert(
        header::AGE,
        response_wrapper
            .cache_policy
            .age(SystemTime::now())
            .as_secs()
            .into(),
    );
    if cache_hit {
        response
            .headers_mut()
            .insert(AIGIS_CACHE_HEADER, AIGIS_CACHE_HEADER_VALUE_HIT);
    }
    Ok(response)
}
