#!/usr/bin/env bash

set -x

copy_file_if_not_exist()
{
	if [ ! -f "$2" ]; then
		cp "$1" "$2"
	fi
}

copy_file_if_not_exist client.db client/live_client.db
copy_file_if_not_exist client.db gui/live_client.db
copy_file_if_not_exist client.db ./live_client.db
copy_file_if_not_exist server.db server/live_server.db
copy_file_if_not_exist server.db ./live_server.db
