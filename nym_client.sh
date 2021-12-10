#!/bin/bash

set -x

which nym-client
if [ $? -ne 0 ]; then
	echo "Please install nym-client v.0.11.0 on your machine."
fi

gateway="4iCkAvZEmKCFX9ubCiAjN6J5EoeQ87XWq89CdCCuZhH2"
nym-client init --id nymdrive-requester-client --gateway ${gateway}

until nym-client run --id nymdrive-requester-client; do
    echo "nym client could not connect, retrying in 2 seconds.."
    sleep 2
done
