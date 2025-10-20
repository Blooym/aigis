use crate::server::AppState;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use reqwest::header;
use scraper::{Html, Selector};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};
use tracing::warn;
use url::Url;

#[derive(Serialize)]
pub struct MetadataResponse {
    title: Option<String>,
    description: Option<String>,
    image_url: Option<String>,
    url: Option<String>,
}

#[derive(Serialize)]
pub struct MetadataError {
    message: &'static str,
}

pub async fn metadata_handler(
    State(state): State<Arc<AppState>>,
    Path(url): Path<Url>,
) -> Result<Response, (StatusCode, Json<MetadataError>)> {
    static META_SELECTOR: LazyLock<Selector> =
        LazyLock::new(|| Selector::parse("meta").expect("valid meta selector"));

    let response = state.client.get(url.as_str()).send().await.map_err(|err| {
        warn!("Failed to fetch page for metadata: {err:?}");
        (
            StatusCode::BAD_GATEWAY,
            Json(MetadataError {
                message: "Failed to send request to upstream server.",
            }),
        )
    })?;

    // Ensure that the Content-Length is below the servers max size.
    //
    // NOTE: This does not guarantee that the content is the size it reports.
    if let Some(content_length) = response.content_length()
        && content_length > state.settings.proxy_settings.max_content_length
    {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(MetadataError {
                message: "Refusing to fetch requested content as it exceeds the maximum size.",
            }),
        ));
    };

    let headers = response.headers().clone();
    let get_meta_tag = {
        // Fetch the page text.
        //
        // TODO: Cap to max size.
        let page = response.text().await.map_err(|err| {
            warn!("Failed to read page content: {err:?}");
            (
                StatusCode::BAD_GATEWAY,
                Json(MetadataError {
                    message: "Failed to read response from upstream server.",
                }),
            )
        })?;

        let document = Html::parse_document(&page);
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
                .find_map(|key| meta.get(*key))
                .map(|s| s.trim().to_owned())
        }
    };

    let mut response = Json(MetadataResponse {
        title: get_meta_tag(&["og:title", "twitter:title", "title"]),
        description: get_meta_tag(&["og:description", "twitter:description", "description"]),
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
    })
    .into_response();

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
