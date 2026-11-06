# A rootcard home (rootcard.org by default): one static binary with the site and the host embedded.
# Another home: docker build --build-arg ROOTCARD_HOME=homes/example/home.toml .
FROM rust:1.95-bookworm AS build
ARG ROOTCARD_HOME=home.toml
WORKDIR /src
COPY . .
RUN ROOTCARD_HOME=$ROOTCARD_HOME cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --home /data rootcard && mkdir -p /data && chown rootcard /data
COPY --from=build /src/target/release/rootcard-site /usr/local/bin/rootcard-site
USER rootcard
WORKDIR /data
ENV ROOTCARD_SITE_BIND=0.0.0.0:8080 \
    ROOTCARD_SITE_DB=/data/rootcard-site.db \
    ROOTCARD_SITE_KEY_FILE=/data/host.key \
    ROOTCARD_SITE_TRUST_PROXY=1
VOLUME /data
EXPOSE 8080
CMD ["rootcard-site"]
