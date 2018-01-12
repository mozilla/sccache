#!/bin/bash
set -ex

case "$TARGET" in
    x86_64-*)
        OPENSSL_TARGET=linux-x86_64
        ;;
    i686-*)
        OPENSSL_TARGET=linux-generic32
        EXTRA=-m32
        ;;
esac

rustup target add "$TARGET"
curl https://www.openssl.org/source/openssl-1.0.2l.tar.gz | tar xzf -
cd openssl-1.0.2l
CC=musl-gcc ./Configure --prefix="$OPENSSL_DIR" no-dso no-ssl2 no-ssl3 "$EXTRA" "$OPENSSL_TARGET" -fPIC
make -j"$(nproc)"
make install
