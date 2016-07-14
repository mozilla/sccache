#!/bin/bash
set -e

if ! test -d "$1"; then
    echo "Usage: upload-tooltool.sh <destination directory>"
    exit 1
fi

tooltool=$(realpath "$(dirname $0)/tooltool.py")
for d in "$1"/*; do
    pushd $d
    chmod -x sccache2.tar.xz
    rm -f releng.manifest
    python "$tooltool" add -v --visibility=public -m releng.manifest sccache2.tar.xz
    python "$tooltool" upload -v -m releng.manifest  --message "Build of sccache2 from revision $(cat REV)" --authentication-file ~/tooltool-upload-token
    popd
done
