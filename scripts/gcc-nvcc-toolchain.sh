#! /usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
set -o xtrace
shopt -s globstar

cd $(dirname "$(realpath "$0")")/../

rm -rf /tmp/gcc-nvcc-toolchain /tmp/gcc-nvcc-toolchain.tgz

mkdir -p /tmp/gcc-nvcc-toolchain

pids=""

for x in gcc g++ nvcc; do
    # RUST_BACKTRACE=1 RUST_LOG=trace SCCACHE_LOG=trace \
    bash -l <<< "\
./target/release/sccache --package-toolchain $(which $x) /tmp/$x-toolchain.tgz; \
tar -xzf /tmp/$x-toolchain.tgz -C /tmp/gcc-nvcc-toolchain/; \
rm /tmp/$x-toolchain.tgz;" &
    pids="${pids:+$pids }$!"
done

# Kill the background procs on EXIT
trap 'ERRCODE=$? && [[ "$pids" != "" ]] && kill -9 ${pids} >/dev/null 2>&1 || true && exit $ERRCODE' ERR EXIT INT ABRT HUP QUIT TERM

echo "sccache --package-toolchain pids: $pids"

wait ${pids};

cd /tmp/gcc-nvcc-toolchain/

tar -I pigz -cf /tmp/gcc-nvcc-toolchain.tgz *

cd - >/dev/null

# tar -t -f /tmp/gcc-nvcc-toolchain.tgz | less
