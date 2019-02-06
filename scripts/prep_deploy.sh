#!/bin/bash

name="sccache-$TRAVIS_TAG-$TARGET"
mkdir $name
cp target/$TARGET/release/sccache $name/
cp README.md LICENSE $name/
tar czvf $name.tar.gz $name
chksum=($(shasum -ba 256 $name.tar.gz))
echo "$chksum" > $name.tar.gz.sha256
