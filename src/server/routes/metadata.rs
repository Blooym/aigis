use crate::server::{
    AppState,
    cache::{CacheSize, CachedResponse},
    routes::{AIGIS_CACHE_HEADER, AIGIS_CACHE_HEADER_VALUE_HIT, ErrorResponse},
};
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use http_cache_semantics::CachePolicy;
use reqwest::header;
use scraper::{Html, Selector};
use serde::Serialize;
use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{Arc, LazyLock},
    time::SystemTime,
};
use tracing::{debug, warn};
use url::Url;

static META_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("meta").expect("valid meta selector"));

#[derive(Clone, Serialize)]
pub struct MetadataResponse {
    pub title: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub url: Option<String>,
}

#[derive(Clone)]
pub struct MetadataResponseWrapper {
    pub response: Json<MetadataResponse>,
    pub headers: HeaderMap,
    pub cache_policy: Arc<CachePolicy>,
}

impl CacheSize for MetadataResponseWrapper {
    fn cache_size_shallow(&self) -> usize {
        std::mem::size_of::<Self>()
            + [
                &self.response.title,
                &self.response.description,
                &self.response.image_url,
                &self.response.url,
            ]
            .into_iter()
            .flatten()
            .map(|s| s.capacity())
            .sum::<usize>()
            + self.headers.capacity()
    }
}

pub async fn metadata_handler(
    State(state): State<Arc<AppState>>,
    Path(url): Path<Url>,
    request_headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let cache_key = {
        let mut hasher = DefaultHasher::new();
        hasher.write(b"metadata");
        url.hash(&mut hasher);
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
        Some((CachedResponse::Metadata(response_wrapper), _))
            if !response_wrapper.cache_policy.is_stale(SystemTime::now()) =>
        {
            // Check if conditional request and handle accordingly.
            if request_headers
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .map(|etag| etag == cache_key.to_string())
                .unwrap_or(false)
            {
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

            // Ensure that the Content-Length is below the servers max size.
            //
            // NOTE: This does not guarantee that the content is the size it reports.
            if let Some(content_length) = response.content_length()
                && content_length > state.server_settings.proxy_settings.max_content_length
            {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(ErrorResponse {
                        message: "Refusing to fetch requested content as it exceeds the maximum size.",
                    }),
                ));
            };

            let get_meta_tag = {
                let response_body = {
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

                let document = Html::parse_document(&String::from_utf8_lossy(&response_body));
                let meta: HashMap<String, String> = document
                    .select(&META_SELECTOR)
                    .filter_map(|element| {
                        let elem = element.value();
                        let property = elem.attr("property").or_else(|| elem.attr("name"))?;
                        let content = elem.attr("content")?;
                        Some((property.to_string(), content.to_string()))
                    })
                    .collect();

                move |keys: &[&str]| -> Option<String> {
                    keys.iter()
                        .find_map(|key| meta.get(*key).map(|s| s.trim().to_owned()))
                }
            };

            let response = Json(MetadataResponse {
                title: get_meta_tag(&["og:title", "twitter:title", "title"]),
                description: get_meta_tag(&[
                    "og:description",
                    "twitter:description",
                    "description",
                ]),
                url: get_meta_tag(&["og:url"]),
                image_url: get_meta_tag(&[
                    "og:image",
                    "og:image:secure_url",
                    "twitter:image",
                    "twitter:image:src",
                ])
                .and_then(|img_url| {
                    let trimmed = img_url.trim();
                    if trimmed.starts_with('/') {
                        url.join(trimmed).ok().map(|u| u.to_string())
                    } else {
                        Some(if trimmed.len() == img_url.len() {
                            img_url
                        } else {
                            trimmed.to_owned()
                        })
                    }
                }),
            });

            let mut response_headers_to_cache = HeaderMap::new();
            response_headers_to_cache.insert(header::ETAG, cache_key.into());
            response_headers_to_cache.insert(AIGIS_CACHE_HEADER, AIGIS_CACHE_HEADER_VALUE_HIT);
            if let Some(cache_control_header) = response_headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()?.parse().ok())
            {
                response_headers_to_cache.insert(header::CACHE_CONTROL, cache_control_header);
            }

            let wrapper = MetadataResponseWrapper {
                response,
                headers: response_headers_to_cache,
                cache_policy: Arc::new(cache_policy),
            };
            if wrapper.cache_policy.is_storable() {
                state
                    .response_cache
                    .insert(
                        cache_key,
                        (
                            CachedResponse::Metadata(wrapper.clone()),
                            wrapper.cache_policy.time_to_live(SystemTime::now()),
                        ),
                    )
                    .await;
            }

            (wrapper, false)
        }
    };

    let mut response = response_wrapper.response.into_response();
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
