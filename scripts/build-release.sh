#!/bin/bash
set -e

if ! test -d "$1"; then
    echo "Usage: build-release.sh <destination directory>"
    exit 1
fi


pushd "$(dirname $0)/.."
system=$(uname -s)

tmpdir=$(mktemp -d)
stagedir=$tmpdir/sccache2
mkdir $stagedir
case $system in
    MINGW*|MSYS_NT*)
	system=Windows
        rm -rf target/release
        cargo build --release && cargo test --release
        cp target/release/sccache.exe "$stagedir"
        compress=bz2
        ;;
    Linux)
        # Build using rust-musl-builder
        rm -rf target/x86_64-unknown-linux-musl/release
        docker run --rm -it -v "$(pwd)":/home/rust/src -v ~/.cargo/git:/home/rust/.cargo/git -v ~/.cargo/registry:/home/rust/.cargo/registry luser/rust-musl-builder sh -c "cargo build --release && cargo test --release"
        cp target/x86_64-unknown-linux-musl/release/sccache "$stagedir"
        strip "$stagedir/sccache"
        compress=xz
        ;;
    Darwin)
        rm -rf target/release
        export MACOSX_DEPLOYMENT_TARGET=10.7 OPENSSL_STATIC=1
        cargo build --release && cargo test --release
        cp target/release/sccache "$stagedir"
        strip "$stagedir/sccache"
        compress=bz2
        ;;
    *)
        echo "Don't know how to build a release on this platform"
        exit 1
        ;;
esac

case ${compress} in
    bz2)
        cflag=j
        ;;
    xz)
        cflag=J
        ;;
    *)
        echo "Unhandled compression ${compress}"
        exit 1
        ;;
esac

destdir="$1/$system"
if test -d "$destdir"; then
    rm -rf "$destdir"
fi
mkdir -p "$destdir"
git rev-parse HEAD > "$destdir/REV"
cd "$tmpdir"
tar c${cflag}vf sccache2.tar.${compress} sccache2
cp sccache2.tar.${compress} "$destdir"
popd
rm -rf "$tmpdir"
