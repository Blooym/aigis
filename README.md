# Aigis

A simple and configurable content proxy.

## Note

**Aigis is a hobby project, is not considered production ready, and has an unstable API.** Anything about it, including features and functionality, is subject to change until stablised. This project is designed with my own infrastructure and needs in mind, and may not be a perfect fit for yours. Be sure to look at other options such as [imageproxy](https://github.com/willnorris/imageproxy) or [ImageWizard](https://github.com/usercode/ImageWizard).

## Features

* [x] Content transformations via query parameters.
  * [x] Image format and size.
* [x] Request caching that respects `Cache-Control` headers.
* [x] `Content-Type` allow-list with wildcard support.
* [x] 'Embed' endpoint that turns OpenGraph meta tags into JSON. 
* [ ] Subdomain wildcard support for `--proxy-allowed-domains`.

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
cargo install aigis
```

## Configuration

Aigis is configured via command-line flags or environment variables and has full support for configuration information from`.env` files. Below is a list of all supported configuration options. You can also run `aigis --help` to get up-to-date help including default values.

| Name                         | Description                                                                                                                                 | Flag                             | Env                                  |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | ------------------------------------ |
| Address                      | Internet socket address that the server should be ran on                                                                                    | `--address`                      | `AIGIS_ADDRESS`                      |
| Request Timeout              | Maximum waiting time for incoming requests before aborting (in seconds)                                                                     | `--request-timeout`              | `AIGIS_REQUEST_TIMEOUT`              |
| Upstream Request Timeout     | Maximum waiting time for upstream requests before aborting (in seconds)                                                                     | `--upstream-request-timeout`     | `AIGIS_UPSTREAM_REQUEST_TIMEOUT`     |
| Upstream Max Redirects       | Maximum amount of redirects to follow when making upstream requests before aborting                                                         | `--upstream-max-redirects`       | `AIGIS_UPSTREAM_MAX_REDIRECTS`       |
| Upstream Forwarded Headers   | A list of header names that should be passed from the original request to the upstream if they are set. Leave empty to not pass any headers | `--upstream-forwarded-headers`   | `AIGIS_UPSTREAM_FORWARDED_HEADERS`   |
| Upstream Allow Invalid Certs | DANGEROUS: Allow self-signed/invalid/forged TLS certificates when making upstream requests                                                  | `--upstream-allow-invalid-certs` | `AIGIS_UPSTREAM_ALLOW_INVALID_CERTS` |
| Proxy Max Content Length     | Maximum Content-Length that can be proxied by this server                                                                                   | `--proxy-max-content-length`     | `AIGIS_PROXY_MAX_CONTENT_LENGTH`     |
| Proxy Allowed Mimetypes      | A list of MIME "essence" strings that are allowed to be proxied by this server. Supports type wildcards (e.g. 'image/*')                    | `--proxy-allowed-mimetypes`      | `AIGIS_PROXY_ALLOWED_MIMETYPES`      |
| Proxy Allowed Domains        | A list of domains that content is allowed to be proxied. When left empty all domains are allowed. Does not support wildcards                | `--proxy-allowed-domains`        | `AIGIS_PROXY_ALLOWED_DOMAINS`        |
| Proxy Max Rescale Resolution | Maximum resolution (inclusive) that is allowed to be requested when proxying content that supports modification at runtime                  | `--proxy-max-rescale-res`        | `AIGIS_PROXY_MAX_RESCALE_RES`        |
