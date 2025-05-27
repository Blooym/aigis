# Aigis

*You are looking at the README for the Aigis binary. If you want to run Aigis as apart of a Rust library you should use [this](https://crates.io/crates/aigis) instead.*

A simple and configurable content proxy aimed at websites that want to embed image and video content from external sources whilst protecting user privacy.

## Notice

**Aigis is a hobby project, is not considered production ready, and has an unstable API.** Anything about it including features, functionality and performance is subject to rapid change until stablised. This project is designed with my own infrastructure and needs in mind and may not be a perfect fit for yours. Be sure to look at other options such as [imageproxy](https://github.com/willnorris/imageproxy) or [ImageWizard](https://github.com/usercode/ImageWizard) as well!

## Features

* [x] Image modifications via query parameters.
* [x] Request caching that respects `Cache-Control` headers.
* [x] `Content-Type` allow-list with wildcard support.
* [ ] 'Embed' endpoint that turns OpenGraph meta tags into a JSON format for use in frontend applications that embed content.
* [ ] Subdomain wildcard support for `--proxy-allowed-domains`

## Installing

### Docker

An official Docker image is published to [GHCR](https://ghcr.io/blooym/aigis) upon every release and is the recommended way to run the server.

Assuming you have Docker or another container tool installed locally simply run the following (replace `<tag>` with the version you would like to use).

```
docker run --name aigis -p 3005:3005 ghcr.io/blooym/aigis:<tag>
```

### Cargo

Assuming you already have Cargo installed locally you can simply run following to compile the binary yourself:

```
cargo install aigis-bin
```

## Configuration

Aigis is configured via command-line flags or environment variables and has full support for configuration information from`.env` files. Below is a list of all supported configuration options. You can also run `aigis --help` to get an up-to-date including default values.

| Name                              | Description                                                                                                                                             | Flag                             | Env                                         |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | ------------------------------------------- |
| Address                           | The socket address that the local server should be hosted on                                                                                            | `--address`                      | `AIGIS_ADDRESS`                             |
| Request Timeout                   | The maximum lifetime of an incoming request before it is forcefully terminated                                                                          | `--request-timeout`              | `AIGIS_REQUEST_TIMEOUT`                     |
| Allow invalid certs from upstream | Allow self-signed/invalid/forged TLS certificates when making upstream requests (Dangerous)                                                             | `--upstream-allow-invalid-certs` | `AIGIS_UPSTREAM_ALLOW_INVALID_CERTS`        |
| Upstream request timeout          | The maximum lifetime of an upstream request before it is forcefully terminated (in seconds)                                                             | `--upstream-request-timeout`     | `AIGIS_UPSTEAM_REQUEST_TIMEOUT`             |
| Upstream max redirects            | The maximum amount of redirects to follow when making upstream requests                                                                                 | `--upstream-max-redirects`       | `AIGIS_UPSTREAM_MAX_REDIRECTS`              |
| Use received cache headers        | Whether or not to send the client the `Cache-Control` header value that was received when making the request to the upstream server if one is available | `--use-received-cache-headers`   | `AIGIS_UPSTREAM_USE_RECEIVED_CACHE_HEADERS` |
| Pass headers to upstream          | A list of header names that should be passed from the original request to the upstream if they are set.                                                 | `--upstream-pass-headers`        | `AIGIS_UPSTREAM_PASS_HEADERS`               |
| Proxy max content size            | The maximum Content-Length that can be proxied by this server                                                                                           | `--proxy-max-size`               | `AIGIS_PROXY_MAX_SIZE`                      |
| Proxy allowed mimetypes           | A list of MIME "essence" strings that are allowed to be proxied by this server. Supports type wildcards (e.g. 'image/*')                                | `--proxy-allowed-mimetypes`      | `AIGIS_PROXY_ALLOWED_MIMETYPES`             |
| Proxy allowed domains             | A list of domains that content is allowed to be proxied. When left empty all domains are allowed. Does not support wildcards                            | `--proxy-allowed-domains`        | `AIGIS_PROXY_ALLOWED_DOMAINS`               |
| Proxy max upscale resolution      | The maximum resolution (inclusive) that is allowed to be requested when proxying content that supports modification at runtime                          | `proxy-max-upscale-res`          | `AIGIS_PROXY_MAX_UPSCALE_RES`               |

## License

Aigis is dual-licensed under both the [MIT License](./LICENSE-MIT) and [Apache 2.0 license](./LICENSE-APACHE) at your choice.