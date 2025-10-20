use anyhow::Context;
use axum::{
    Json,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Serialize)]
struct MetadataResponse {
    title: Option<String>,
    description: Option<String>,
    image: Option<String>,
}

#[derive(Debug, Serialize)]
struct MetadataError<'a> {
    message: &'a str,
}

pub async fn metadata_handler(Path(url): Path<Url>) -> Response {
    let page = match reqwest::get(url).await {
        Ok(res) => res.text().await.context("failed to get page text").unwrap(),
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(MetadataError {
                    message: "Failed to send request to upstream server.",
                }),
            )
                .into_response();
        }
    };

    // Snippet from revoltapp/january
    let mut meta = {
        let html = Html::parse_document(&page);
        let selector = Selector::parse("meta").unwrap();
        let mut meta = HashMap::new();
        for ele_ref in html.select(&selector) {
            let ele = ele_ref.value();
            if let (Some(prop), Some(content)) = (
                ele.attr("property").or_else(|| ele.attr("name")),
                ele.attr("content"),
            ) {
                meta.insert(prop.to_string(), content.to_string());
            }
        }
        meta
    };
    Json(MetadataResponse {
        title: meta
            .remove("og:title")
            .or_else(|| meta.remove("twitter:title"))
            .or_else(|| meta.remove("title"))
            .map(|s| s.trim().to_owned()),
        description: meta
            .remove("og:description")
            .or_else(|| meta.remove("twitter:description"))
            .or_else(|| meta.remove("description"))
            .map(|s| s.trim().to_owned()),
        image: meta
            .remove("og:image")
            .or_else(|| meta.remove("og:image:secure_url"))
            .or_else(|| meta.remove("twitter:image"))
            .or_else(|| meta.remove("twitter:image:src"))
            .map(|s| s.trim().to_owned())
            .map(|mut url| {
                if let Some(ch) = url.chars().next() {
                    if ch == '/' {
                        url = format!("{}{}", &url.trim_end_matches('/'), url);
                    }
                }
                url
            }),
    })
    .into_response()
}
