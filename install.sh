#!/usr/bin/sh

PWD=$(pwd)

make
sed -i -E 's|^(INSTALLATION_PATH = )".*"$|\1"'"$PWD"'"|' ./main.py
sed -i -E 's|^(INSTALLATION_PATH = )".*"$|\1"'"$PWD"'"|' ./gdb_daemon.py
sudo ln -f -s $PWD/main.py /usr/bin/fsop-target-finder