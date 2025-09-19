#!/usr/bin/sh

PWD=$(pwd)

make -C $PWD/src --quiet
sed -i -E 's|^(INSTALLATION_PATH = )".*"$|\1"'"$PWD"'"|' $PWD/src/constants.py
sudo ln -f -s $PWD/src/find_vtable_offset.py /usr/bin/fsop-target-finder