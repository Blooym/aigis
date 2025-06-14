# Aigis

*You are looking at the README for the Aigis library. If you just want to run Aigis you should use [the binary](https://crates.io/crates/aigis-bin) instead.*

A simple and configurable content proxy, created to allow websites to embed image and video from external sources whilst protecting user privacy.

## Notice

**Aigis is a hobby project, is not considered production ready, and has an unstable API.** Anything about it including features, functionality and performance is subject to rapid change until stablised. This project is designed with my own infrastructure and needs in mind and may not be a perfect fit for yours. Be sure to look at other options such as [imageproxy](https://github.com/willnorris/imageproxy) or [ImageWizard](https://github.com/usercode/ImageWizard) as well!

## Features

| Name            | Description                                                                                                                 | Default? |
| --------------- | --------------------------------------------------------------------------------------------------------------------------- | -------- |
| `rustls-tls`    | Use [`rustls`](https://github.com/rustls/rustls) when making upstream requests                                              | `yes`    |
| `native-tls`    | Use the system's native TLS when making upstream requests                                                                   | `no`     |
| `cache-moka`    | Enable upstream response caching using [`moka`](https://github.com/moka-rs/moka) (respecting `Cache-Control` headers)       | `yes`    |
| `cache-cacache` | Enable upstream response caching using [`cacache`](https://github.com/zkat/cacache-rs) (respecting `Cache-Control` headers) | `no`     |

## Documentation

Documentation is automatically generated from code comments and is available to view on [docs.rs](https://docs.rs/releases/search?query=aigis).
