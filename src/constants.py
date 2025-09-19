import os
from typing import TypedDict

INSTALLATION_PATH = "/home/pwnguy/Tools/fsop/fsop_target_finder"
EXE_FILENAME = f"{INSTALLATION_PATH}/target"
PARAMS_FILE = f"{INSTALLATION_PATH}/param.txt"
CUSTOM_STREAMS_PATH = f"{INSTALLATION_PATH}/custom_streams"
DEFAULT_LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
DEFAULT_LINKER = "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"

VTABLES_NUM = 17
JUMP_T_SIZE = 0xa8
VTABLE_LEN = VTABLES_NUM * JUMP_T_SIZE
STD_STREAMS = ["stdin", "stdout", "stderr"]

STRONG_CHECK = False
DEBUG = True
INTERACTIVE = False

VTABLE_OFFSET_DAEMON = f"{INSTALLATION_PATH}/src/gdb_find_vtable_offset.py"
FIND_WFILE_OVERFLOW_DAEMON = f"{INSTALLATION_PATH}/src/gdb_find_wfile_overflow.py"

class Stream(TypedDict):
    _flags : int
    _IO_read_ptr : int
    _IO_read_end : int
    _IO_read_base : int
    _IO_write_base : int
    _IO_write_ptr : int
    _IO_write_end : int
    _IO_buf_base : int
    _IO_buf_end : int
    _IO_save_base : int
    _IO_backup_base : int
    _IO_save_end : int
    _markers : int
    _chain : int
    _fileno : int
    _flags2 : int
    _old_offset : int
    _cur_column : int
    _vtable_offset : int
    _shortbuf : int
    _lock : int
    _offset : int
    _codecvt : int
    _wide_data : int
    _freeres_list : int
    _freeres_buf : int
    __pad5 : int
    _mode : int
    _unused2 : bytes
    vtable : int

def get_custom_streams():
    return os.listdir(f"{CUSTOM_STREAMS_PATH}")