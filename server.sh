#!/usr/bin/env bash

set -x

./copy_db.sh

cd server
RUST_BACKTRACE=1 RUST_LOG=server cargo run --release
