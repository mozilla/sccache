#!/bin/bash
set -e

if ! test -d "$1"; then
    echo "Usage: upload-tooltool.sh <destination directory>"
    exit 1
fi

export tooltool=$(realpath "$(dirname $0)/tooltool.py")
upload_one() {
    cd $1
    chmod -x sccache2.tar.*
    rm -f releng.manifest
    python "$tooltool" add -v --visibility=public --unpack -m releng.manifest sccache2.tar.*
    python "$tooltool" upload -v -m releng.manifest  --message "Build of sccache2 from revision $(cat REV)" --authentication-file ~/tooltool-upload-token
}
export -f upload_one

dirs="$1"/*
if which parallel >/dev/null; then
    parallel --linebuffer upload_one ::: ${dirs}
else
  for d in ${dirs}; do
      upload_one $d
  done
fi
