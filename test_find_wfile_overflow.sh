#!/bin/bash

gdb -q --nx -ex "set debuginfod enable on" -ex "source gdb_find_wfile_overflow.py"