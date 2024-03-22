FROM rust:1-alpine
RUN apk add --update git build-base
RUN adduser --disabled-password --gecos "" dev
USER dev
RUN rustup component add rustfmt clippy