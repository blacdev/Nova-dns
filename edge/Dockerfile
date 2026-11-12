# The tunnel's edge (edge/README in ../README.md, "Edge host"): one small static-ish binary.
FROM rust:1-bookworm AS build
WORKDIR /edge
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /edge/target/release/nova-edge /usr/local/bin/nova-edge
USER nobody
ENTRYPOINT ["nova-edge"]
