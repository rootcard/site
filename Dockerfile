# rootcard.org: one static binary with the site and the host embedded.
FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --home /data rootcard && mkdir -p /data && chown rootcard /data
COPY --from=build /src/target/release/rootcard-site /usr/local/bin/rootcard-site
USER rootcard
WORKDIR /data
ENV ROOTCARD_SITE_BIND=0.0.0.0:8080 \
    ROOTCARD_SITE_DB=/data/rootcard-site.db \
    ROOTCARD_SITE_KEY_FILE=/data/host.key \
    ROOTCARD_SITE_URLS=https://rootcard.org \
    ROOTCARD_SITE_TRUST_PROXY=1
VOLUME /data
EXPOSE 8080
CMD ["rootcard-site"]
