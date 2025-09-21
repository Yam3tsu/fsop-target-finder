#!/usr/bin/sh

PWD=$(pwd)

make -C $PWD/src --quiet
sed -i -E 's|^(INSTALLATION_PATH = )".*"$|\1"'"$PWD"'"|' $PWD/src/modules/constants.py
sed -i -E 's|^(INSTALLATION_PATH = )".*"$|\1"'"$PWD"'"|' $PWD/src/modules/gdb_find_vtable_offset.py
sed -i -E 's|^(INSTALLATION_PATH = )".*"$|\1"'"$PWD"'"|' $PWD/src/modules/gdb_find_wfile_overflow.py
sudo ln -f -s $PWD/src/find_vtable_offset.py /usr/bin/fsop-find-vtable-offset
sudo ln -f -s $PWD/src/find_wfile_overflow.py /usr/bin/fsop-wfile-overflow-finder