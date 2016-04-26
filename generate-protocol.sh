#!/bin/sh
#
# You must have protoc installed, as well as rust-protobuf installed and
# in your $PATH.
# On Ubuntu, `apt-get install protobuf-compiler` for protoc,
# and `cargo install protobuf` for rust-protobuf and follow the advice
# it outputs about $PATH.

d=$(dirname $0)
protoc --rust_out ${d}/src ${d}/protocol.proto
