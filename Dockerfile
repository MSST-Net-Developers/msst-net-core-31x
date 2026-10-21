# syntax=docker/dockerfile:1
#
# MSST-Net Core image (3.1).  Build from the repository root:
#
#   docker buildx build -t abjust/msstnet31x-core .
#
# Run with host networking, NET_ADMIN and /dev/net/tun, the /var/lib/msst
# volume (identity, core.toml) and the IPC socket directory shared with the
# Controller container; see docs/DOCKER.md in msst-net-controller-31x.

FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY src src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin msst-net-core \
    && cp target/release/msst-net-core /usr/local/bin/

FROM debian:bookworm-slim
# Core runs `ip` (TUN setup) and `iptables` (DNS redirect when there is no
# systemd-resolved, as in a container).
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/msst-net-core /usr/local/bin/msst-net-core
COPY LICENSE THIRD_PARTY_LICENSES.txt /usr/share/doc/msst-net-core/
# Config and data in /var/lib/msst (the 3.0.x volume).
ENV CORE_MODE=container
VOLUME ["/var/lib/msst"]
ENTRYPOINT ["msst-net-core"]
