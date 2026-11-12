# The tunnel's edge (README, "Edge host"): one small binary.
FROM rust:1-bookworm AS build
WORKDIR /edge
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libcap2-bin && rm -rf /var/lib/apt/lists/*
COPY --from=build /edge/target/release/nova-edge /usr/local/bin/nova-edge
# It runs as nobody, and a process that is not root may not take a port below 1024 (UDP 443)
# unless its program file carries the right to: cap_add in the Compose file only lets the
# container have it. Set here, in this stage (COPY does not keep it), on this one file.
RUN setcap cap_net_bind_service=+ep /usr/local/bin/nova-edge
USER nobody
ENTRYPOINT ["nova-edge"]
