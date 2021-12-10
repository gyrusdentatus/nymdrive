#!/usr/bin/env bash

set -x

which sqlitebrowser

if [ $? -ne 0 ]; then
	echo ""
	echo "Please install sqlitebrowser on your machine to view file hashes!"
	echo ""
	echo "Ubuntu/Debian: sudo apt install sqlitebrowser"
	echo "Arch Linux:    sudo pacman -S sqlitebrowser"
	echo "MacOS:         brew install --cask db-browser-for-sqlite"
	echo ""
else
	sqlitebrowser --table files ./gui/live_client.db
fi
