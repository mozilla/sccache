#!/bin/sh
set -o errexit
set -o pipefail
set -o nounset
set -o xtrace

#CARGO="cargo --color=always"
CARGO="cargo"

gnutarget=x86_64-unknown-linux-gnu
wintarget=x86_64-pc-windows-gnu

gnutarget() {
    unset OPENSSL_DIR
    export OPENSSL_STATIC=1
    target=$gnutarget
}
wintarget() {
    export OPENSSL_DIR=$(pwd)/openssl-win
    export OPENSSL_STATIC=1
    target=$wintarget
}

# all-windows doesn't work as redis-rs build.rs has issues (checks for cfg!(unix))

if [ "$1" = checkall ]; then
    $CARGO check --target $target --all-targets --features 'all dist-client dist-server dist-tests'
    $CARGO check --target $target --all-targets --features 'all dist-client dist-server'
    $CARGO check --target $target --all-targets --features 'all dist-client dist-tests'
    $CARGO check --target $target --all-targets --features 'all dist-server dist-tests'
    $CARGO check --target $target --all-targets --features 'all dist-client'
    $CARGO check --target $target --all-targets --features 'all dist-server'
    $CARGO check --target $target --all-targets --features 'all dist-tests'
    $CARGO check --target $target --all-targets --features 'all'
    $CARGO check --target $target --all-targets --features 'dist-client dist-server dist-tests'
    $CARGO check --target $target --all-targets --features 'dist-client dist-server'
    $CARGO check --target $target --all-targets --features 'dist-client dist-tests'
    $CARGO check --target $target --all-targets --features 'dist-server dist-tests'
    $CARGO check --target $target --all-targets --features 'dist-client'
    $CARGO check --target $target --all-targets --features 'dist-server'
    $CARGO check --target $target --all-targets --features 'dist-tests'
    $CARGO check --target $target --all-targets --features ''
    $CARGO check --target $target --all-targets --no-default-features --features 'all dist-client dist-server dist-tests'
    $CARGO check --target $target --all-targets --no-default-features --features 'all dist-client dist-server'
    $CARGO check --target $target --all-targets --no-default-features --features 'all dist-client dist-tests'
    $CARGO check --target $target --all-targets --no-default-features --features 'all dist-server dist-tests'
    $CARGO check --target $target --all-targets --no-default-features --features 'all dist-client'
    $CARGO check --target $target --all-targets --no-default-features --features 'all dist-server'
    $CARGO check --target $target --all-targets --no-default-features --features 'all dist-tests'
    $CARGO check --target $target --all-targets --no-default-features --features 'all'
    $CARGO check --target $target --all-targets --no-default-features --features 'dist-client dist-server dist-tests'
    $CARGO check --target $target --all-targets --no-default-features --features 'dist-client dist-server'
    $CARGO check --target $target --all-targets --no-default-features --features 'dist-client dist-tests'
    $CARGO check --target $target --all-targets --no-default-features --features 'dist-server dist-tests'
    $CARGO check --target $target --all-targets --no-default-features --features 'dist-client'
    $CARGO check --target $target --all-targets --no-default-features --features 'dist-server'
    $CARGO check --target $target --all-targets --no-default-features --features 'dist-tests'
    $CARGO check --target $target --all-targets --no-default-features --features ''
    wintarget
    $CARGO check --target $target --all-targets --features 'dist-client'
    #$CARGO check --target $target --all-targets --features 'all-windows dist-client'
    #$CARGO check --target $target --all-targets --features 'all-windows'
    $CARGO check --target $target --all-targets --features ''


elif [ "$1" = test ]; then
    # Musl tests segfault due to https://github.com/mozilla/sccache/issues/256#issuecomment-399254715
    gnutarget
    VERBOSE=
    NOCAPTURE=
    NORUN=
    TESTTHREADS=
    #VERBOSE="--verbose"
    #NORUN=--no-run
    #NOCAPTURE=--nocapture
    TESTTHREADS="--test-threads 1"

    # Since integration tests start up the sccache server they must be run sequentially. This only matters
    # if you have multiple test functions in one file.

    set +x
    if ! which docker; then
        printf "WARNING: =====\n\ndocker not present, some tests will fail\n\n=====\n\n\n\n\n"
        sleep 5
    fi
    if ! which icecc-create-env; then
        printf "WARNING: =====\n\nicecc-create-env not present, some tests will fail\n\n=====\n\n\n\n\n"
        sleep 5
    fi
    set -x

    RUST_BACKTRACE=1 $CARGO test $NORUN --target $target --features 'all dist-client dist-server dist-tests' $VERBOSE -- $NOCAPTURE $TESTTHREADS test_dist_nobuilder

else
    echo invalid command
    exit 1
fi
