#!/bin/bash

gdb -q --nx -ex "set debuginfod enable on" -ex "source ./src/modules/gdb_libc_base.py" -ex "source ./src/modules/gdb_find_wfile_overflow.py"