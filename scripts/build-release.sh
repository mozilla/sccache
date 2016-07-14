#!/bin/bash
set -e

if ! test -d "$1"; then
    echo "Usage: build-release.sh <destination directory>"
    exit 1
fi


pushd "$(dirname $0)/.."
system=$(uname -s)
destdir="$1/$system"
if test -d "$destdir"; then
    rm -rf "$destdir"
fi
mkdir -p "$destdir"
tmpdir=$(mktemp -d)
stagedir=$tmpdir/sccache2
mkdir $stagedir
case $system in
    MINGW*)
        cargo build --release && cargo test --release
        cp "${OPENSSL_LIB_DIR}/../"{ssleay32,libeay32}.dll "$stagedir"
        cp target/release/sccache.exe "$stagedir"
        ;;
    Linux)
        # Build using rust-musl-builder
        docker run --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder sh -c "cargo build --release && cargo test --release"
        cp target/x86_64-unknown-linux-musl/release/sccache "$stagedir"
        strip "$stagedir/sccache"
        ;;
    Darwin)
        cargo build --release && cargo test --release
        cp target/release/sccache "$stagedir"
        strip "$stagedir/sccache"
        ;;
    *)
        echo "Don't know how to build a release on this platform"
        exit 1
    ;;
esac

git rev-parse HEAD > "$destdir/REV"
cd "$tmpdir"
tar cJvf sccache2.tar.xz sccache2
cp sccache2.tar.xz "$destdir"
popd
rm -rf "$tmpdir"
