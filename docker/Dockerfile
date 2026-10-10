FROM rust:alpine AS bootstrap_os
  # hadolint ignore=DL3018
  RUN apk upgrade --update-cache --available

FROM alpine:latest AS bootstrap_cargo_config_scache
  RUN mkdir -p .cargo \
      && { \
        echo '[build]'; \
        echo 'rustc-wrapper = "/bin/sccache"'; \
      } > .cargo/config.toml

FROM bootstrap_os AS bootstrap_build_deps
  RUN set -ex; \
    apk add --no-cache --virtual .rust-builder clang musl-dev make pkgconfig \
    && apk add --no-cache --virtual .bootstrap-sccache libressl-dev \
    && apk add --no-cache --virtual .runtime-sccache libressl


FROM bootstrap_build_deps AS bootstrap_builder
  ENV RUST_BACKTRACE=1 \
      CC=clang \
      CXX=clang++ \
      MAKEOPTS="-j$(getconf _NPROCESSORS_ONLN)"

  WORKDIR /src

  COPY . .

  # Note: more code == more security footprints
  #       add something like the following to limit features to only that in which is used
  #
  # cargo build --release --no-default-features --features=local|s3|redis|gcs|memcached|azure|gha|webdav|oss
  #
  # ref: https://github.com/mozilla/sccache?tab=readme-ov-file#storage-options
  RUN cargo build --release --message-format short \
      && apk del .bootstrap-sccache \
      && apk del .rust-builder

# docker build -f docker/Dockerfile.alpine -t sccache:latest --compress . --target=pipeline
FROM alpine:latest AS pipeline
  # hadolint ignore=SC2016
  RUN --mount=type=bind,source=/etc,target=/mnt_etc,from=bootstrap_os set -ex; \
      apk update \
      && apk add shfmt \
      && apk upgrade --update-cache --available \
      && { \
        echo '#!/bin/sh'; \
        echo 'set -eu'; \
        echo 'if [ "${#}" -gt 0 ] && [ "${1#-}" = "${1}" ] \'; \
        echo '  && command -v "${1}" > "/dev/null" 2>&1; then'; \
        echo '  exec "${@}"'; \
        echo 'else exec /usr/bin/shfmt "${@}"; fi'; \
        echo 'exit 0'; \
      } > /init && chmod +x /init

  COPY --from=bootstrap_builder /src/target/release/sccache /usr/local/cargo/bin/

  WORKDIR /usr/local/cargo/bin

  SHELL [ "/bin/ash", "-o", "pipefail", "-c" ]

  RUN find . -type f -executable -not \( -name '*tkinter*' \) -exec ldd '{}' ';' \
      | awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); gsub(".*/", "", so); print so }' \
      | xargs -r apk search -f | awk '{ so = $(NF-1); gsub(/-\d+.*$/, "", so); print so }' \
      | xargs -r apk add --no-cache --virtual .runtime

  ENV PATH="/usr/local/cargo/bin:${PATH}" \
      RUSTC_WRAPPER="/usr/local/cargo/bin/sccache"

  WORKDIR /root

  HEALTHCHECK --retries=1 --timeout=15s CMD /usr/local/cargo/bin/sccache --version

  ENTRYPOINT [ "/init" ]

FROM scratch
  ENV RUSTC_WRAPPER="/bin/sccache"

  COPY --from=bootstrap_builder /usr/local/cargo/bin/sccache /bin/
  COPY --from=bootstrap_cargo_config_scache /root/.cargo/config.toml ${HOME}/.cargo/config.toml

  ENTRYPOINT [ "/bin/sccache" ]

  CMD [ "/bin/sccache" ]

# vi: nospell
