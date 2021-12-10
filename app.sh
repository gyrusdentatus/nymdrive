#!/usr/bin/env bash

set -x

./copy_db.sh

which cargo
if [ $? -ne 0 ]; then
	echo "Please install rust 1.57+ on your machine."
fi

if [ "$1" != "noauto" ]; then
	cd nym-duplex
	sp="HY1FzvXoy1TurXzGJtoskJQkbs7gjyRDobmVgdPTLRWX.2iAYpXfcraGGuUYavWLNejhWmonYQRkj6pYSamWZGc6b@4iCkAvZEmKCFX9ubCiAjN6J5EoeQ87XWq89CdCCuZhH2"
	RUST_BACKTRACE=1 RUST_LOG=server cargo run --release --bin client -- --service-provider ${sp} &
	cd ..
fi

cd gui
RUST_BACKTRACE=1 RUST_LOG="gui=debug,client=debug" cargo build --release
RUST_BACKTRACE=1 RUST_LOG="gui=debug,client=debug" cargo run --release
