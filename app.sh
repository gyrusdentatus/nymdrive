#!/usr/bin/env bash

set -x

./copy_db.sh

which cargo
if [ $? -ne 0 ]; then
	echo "Please install rust 1.57+ on your machine."
fi

if [ "$1" != "noauto" ]; then
	cd nym-duplex
	sp="DHdzGES2Egbswhb4BMKZuXJ5haFygpM4qErBBZNUmHEL.FGrJ3D1DtBe3howuU9i89u32a6PkwUPJwCfeEVaXe3ha@83x9YyNkQ5QEY84ZU6Wmq8XHqfwf9SUtR7g5PAYB1FRY"
	RUST_BACKTRACE=1 RUST_LOG=server cargo run --release --bin client -- --service-provider ${sp} &
	cd ..
fi

cd gui
RUST_BACKTRACE=1 RUST_LOG="gui=debug,client=debug" cargo build --release
RUST_BACKTRACE=1 RUST_LOG="gui=debug,client=debug" cargo run --release
