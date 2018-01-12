#!/bin/bash
set -ex

case "$TARGET" in
    x86_64-*)
        OPTIONS=(linux-x86_64)
        ;;
    i686-*)
        OPTIONS=(linux-generic32 -m32 -Wl,-melf_i386)
        ;;
esac

rustup target add "$TARGET"
curl https://www.openssl.org/source/openssl-1.0.2l.tar.gz | tar xzf -
cd openssl-1.0.2l
CC=musl-gcc ./Configure --prefix="$OPENSSL_DIR" no-dso no-ssl2 no-ssl3 "${OPTIONS[@]}" -fPIC
make -j"$(nproc)"
make install
