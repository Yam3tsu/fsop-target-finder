#!/bin/bash

gdb -q --nx -ex "set debuginfod enable on" -ex "source ./src/gdb_libc_base.py" -ex "source ./src/gdb_find_wfile_overflow.py"