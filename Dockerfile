# syntax=docker/dockerfile:1

# ---- build stage ---------------------------------------------------------
# rust:*-alpine targets *-unknown-linux-musl and links statically by default,
# so the resulting binary needs no libc at runtime. musl-dev supplies the libc
# headers that ring's C code needs (gcc already ships in the base image).
FROM rust:1.98-alpine3.24 AS builder

RUN apk add --no-cache musl-dev

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# The binary must be copied out inside this same RUN — anything left in the
# cache mounts disappears once the instruction finishes.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && \
    cp target/release/sub-injector /sub-injector

# Minimal account database so the scratch image can run under a named,
# unprivileged user instead of root.
RUN printf 'app:x:10001:10001::/nonexistent:/sbin/nologin\n' > /passwd.app && \
    printf 'app:x:10001:\n' > /group.app

# ---- runtime stage -------------------------------------------------------
# reqwest is built with rustls + webpki-roots, so the Mozilla root store is
# compiled into the binary and no ca-certificates package is required.
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/FolkiDevv/remna-sub-injector" \
      org.opencontainers.image.description="Remnawave subscription injector proxy" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /passwd.app /etc/passwd
COPY --from=builder /group.app  /etc/group
COPY --from=builder /sub-injector /usr/local/bin/sub-injector

WORKDIR /app
ENV CONFIG_FILE=/app/config.toml

USER 10001:10001
EXPOSE 3020
ENTRYPOINT ["/usr/local/bin/sub-injector"]
