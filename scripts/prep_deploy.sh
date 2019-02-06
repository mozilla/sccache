#!/bin/bash

name="sccache-$TRAVIS_TAG-$TARGET"
mkdir $name
cp target/$TARGET/release/sccache $name/
cp README.md LICENSE $name/
tar czvf $name.tar.gz $name
