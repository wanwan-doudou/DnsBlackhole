ARG NODE_IMAGE=node:24-bookworm-slim
ARG RUST_IMAGE=rust:1.98-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${NODE_IMAGE} AS web-builder
WORKDIR /build
RUN npm install --global pnpm@11.25.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY index.html tsconfig.json vite.config.ts ./
COPY src ./src
RUN pnpm build

FROM ${RUST_IMAGE} AS rust-builder
WORKDIR /build
COPY rust-toolchain.toml ./
COPY src-tauri ./src-tauri
COPY --from=web-builder /build/dist ./dist
RUN cargo build \
    --manifest-path src-tauri/Cargo.toml \
    --locked \
    --release \
    --no-default-features \
    --features web-admin \
    --bin dnsblackhole-service

FROM ${RUNTIME_IMAGE} AS runtime
ARG DNSBLACKHOLE_UID=10001
ARG DNSBLACKHOLE_GID=10001
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libcap2-bin tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "${DNSBLACKHOLE_GID}" dnsblackhole \
    && useradd --uid "${DNSBLACKHOLE_UID}" --gid "${DNSBLACKHOLE_GID}" \
        --home-dir /var/lib/dnsblackhole --no-create-home --shell /usr/sbin/nologin dnsblackhole \
    && install --directory --owner=dnsblackhole --group=dnsblackhole --mode=0700 /var/lib/dnsblackhole \
    && install --directory --owner=dnsblackhole --group=dnsblackhole --mode=0755 /run/dnsblackhole
COPY --from=rust-builder /build/src-tauri/target/release/dnsblackhole-service /usr/local/bin/dnsblackhole-service
RUN setcap cap_net_bind_service=+ep /usr/local/bin/dnsblackhole-service \
    && getcap /usr/local/bin/dnsblackhole-service | grep -q cap_net_bind_service

ENV DNSBLACKHOLE_CONTAINER=1
USER 10001:10001
VOLUME ["/var/lib/dnsblackhole"]
EXPOSE 53/udp 53/tcp 3000/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/dnsblackhole-service", "healthcheck"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/dnsblackhole-service"]
CMD ["serve", "--data-dir", "/var/lib/dnsblackhole", "--web-listen", "0.0.0.0:3000"]
