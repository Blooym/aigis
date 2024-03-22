use crate::{mime_util, AppState};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use bytes::Bytes;
use image::{imageops::FilterType, io::Reader, ImageFormat};
use mime::*;
use serde::{Deserialize, Serialize};
use std::{
    io::{BufReader, BufWriter, Cursor},
    str::FromStr,
};
use tracing::{debug, warn};
use url::Url;

/// The endpoint URL for this route with a leading slash.
pub const PROXY_ENDPOINT: &str = "/proxy/:url";

#[derive(Debug, Serialize, Deserialize)]
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

pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(url): Path<Url>,
    headers: HeaderMap,
    query: Query<ProxyRequestQueryParams>,
) -> Response {
    // If allowed_domains is enabled, check if this domain is allowed.
    if let Some(allowed_domains) = state.settings.proxy_settings.allowed_domains {
        if !allowed_domains.contains(&url) {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Proxying for this domain is not enabled"))
                .unwrap();
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
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Failed to make request to upstream server"))
                .unwrap();
        }
        Ok(data) => {
            if let Err(err) = data.error_for_status_ref() {
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(format!(
                        "Upstream server responded with a failure status code: {}",
                        err
                    )))
                    .unwrap();
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
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(
                "Upstream server either did not send or sent an invalid Content-Type header",
            ))
            .unwrap();
    };
    if !mime_util::is_mime_allowed(
        &content_type,
        &state.settings.proxy_settings.allowed_mimetypes,
    ) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(format!(
                "Refusing to proxy the rqeuest content as proxying for '{}' is not enabled on this server",
                content_type.essence_str()
            )))
            .unwrap();
    }

    // Ensure that the Content-Length header value is below the servers max size.
    let Some(content_length) = upstream_response.content_length() else {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(
                "Upstream did not provide Content-Length information",
            ))
            .unwrap();
    };
    if content_length > state.settings.proxy_settings.max_size {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(
                "Refusing to proxy requested content as it exceeds the maximum Content-Length",
            ))
            .unwrap();
    }

    // Ensure that the response contains a response body.
    let Ok(mut req_body_bytes) = upstream_response.bytes().await else {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(
                "Something went wrong whilst obtaining the request body from upstream",
            ))
            .unwrap();
    };

    // If the provided Content-Type is an image and the query requested
    // image changes, apply them.
    if content_type.type_() == mime::IMAGE && (query.0.size.is_some()) || query.0.format.is_some() {
        let Some(mime_image_type) = ImageFormat::from_mime_type(content_type.essence_str()) else {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(
                    "Image modifications were requested on an unsupported content format",
                ))
                .unwrap();
        };
        let image_format = query
            .0
            .format
            .map(|s| ImageFormat::from_extension(s).unwrap())
            .unwrap_or(mime_image_type);

        // Decode image
        let Ok(mut image) =
            Reader::with_format(BufReader::new(Cursor::new(req_body_bytes)), mime_image_type)
                .decode()
        else {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(
                    "Unable to decode image receieved from upstream server",
                ))
                .unwrap();
        };

        let mut buffer: Vec<u8> = Vec::new();

        // Conditionally apply resizing if requested.
        if let Some(resize) = query.0.size {
            debug!("Applying resize to requested image");
            if resize > state.settings.proxy_settings.max_content_resize {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(
                        "The requested image size was too large to be processed by this server",
                    ))
                    .unwrap();
            }
            image = image.resize(resize, resize, FilterType::Nearest);
        }

        // Write image using either the original or requested image format
        // then overwrite the request body and content_type values.
        if image
            .write_to(&mut BufWriter::new(Cursor::new(&mut buffer)), image_format)
            .is_err()
        {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(
                    "An error occured whilst attempting to process image modifications",
                ))
                .unwrap();
        };

        req_body_bytes = Bytes::from_iter(buffer);
        content_type = Mime::from_str(image_format.to_mime_type())
            .expect("image format mime time should be a valid format");
    }

    // Send back the proxied content.
    let mut response = Response::new(Body::from(req_body_bytes));
    response.headers_mut().append(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type.essence_str()).unwrap(),
    );
    response
}
