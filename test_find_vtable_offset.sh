#!/bin/bash

gdb -q --nx -ex "set debuginfod enable on" -ex "source ./src/modules/gdb_find_vtable_offset.py"