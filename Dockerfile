# ----------
#    USER
# ----------
FROM alpine:latest as user
RUN adduser -S -s /bin/false -D aigis
RUN mkdir /data

# -----------
#    BUILD
# -----------
FROM rust:1-alpine as build
WORKDIR /build
RUN apk add --no-cache --update build-base

# Pre-cache cargo dependencies.
COPY ["Cargo.toml", "Cargo.lock", "./"]
COPY crates ./crates
ARG RUSTC_BUILD_FLAGS=--release --bin
RUN cargo build ${RUSTC_BUILD_FLAGS}


# -----------
#   RUNTIME
# -----------
FROM scratch as runtime
WORKDIR /app

COPY --from=build /build/target/release/aigis /usr/bin/aigis

# Import and switch to non-root user.
COPY --from=user /etc/passwd /etc/passwd
COPY --from=user /bin/false /bin/false
USER aigis

ENV AIGIS_ADDRESS=0.0.0.0:3500
ENV RUST_LOG=info
EXPOSE 3500

ENTRYPOINT ["/usr/bin/aigis"]