import os
from typing import TypedDict, get_type_hints
import subprocess

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

STRONG_CHECK = True
DEBUG = False
INTERACTIVE = False

VTABLE_OFFSET_DAEMON = f"{INSTALLATION_PATH}/src/modules/gdb_find_vtable_offset.py"
FIND_WFILE_OVERFLOW_DAEMON = f"{INSTALLATION_PATH}/src/modules/gdb_find_wfile_overflow.py"
BASE_ADDR_DAEMON = f"{INSTALLATION_PATH}/src/modules/gdb_libc_base.py"

INIT_SCRIPT = f'''
    file {EXE_FILENAME}
    b main
    run
'''

class Stream(TypedDict):
    """
    The interface of the Stream object.
    
    This interface is used to check if a given stream is coerent with the C FILE struct.
    """

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
    """
    Retrive the list of custom streams currently aviable
    """
    return os.listdir(f"{CUSTOM_STREAMS_PATH}")

def debug_print(s : str):
    """
    Print a debug message only if the flag DEBUG = True.
    """
    if DEBUG == True:
        for line in s.split("\n"):
            print(f"[DEBUG] {line}")

def gdb_debug_print(s : str):
    """
    It's similar to debug print, but it uses a different prefix.
    
    Used in gdb python scripts.
    """
    if DEBUG == True:
        for line in s.split("\n"):
            print(f"[DAEMON DEBUG] {line}")

def compile_target(libc : str = DEFAULT_LIBC, linker : str = DEFAULT_LINKER):
    """
    It compile the target binary using the given libc and linker.

    - libc -- The full path of the libc to use to copmile target.

    - linker -- The full path of the dynamic linker to use to compile target.
    It's necessary that it is compatible with the libc given.
    """

    libc = os.path.dirname(libc)
    if DEBUG == True:
        return subprocess.run([
        "make",
        f"LIBC_PATH={libc}",
        f"LD={linker}",
        f"-C",
        f"{INSTALLATION_PATH}/src",
        "all",
    ]).returncode
    return subprocess.run([
        "make",
        f"LIBC_PATH={libc}",
        f"LD={linker}",
        f"-C",
        f"{INSTALLATION_PATH}/src",
        "--quiet",
        "all",
    ],
    capture_output=True).returncode

def check_stream(stream : dict | Stream):
    """
    Check if the given stream correctly implements the Stream interface.
    
    - stream -- The stream to check
    """

    props = get_type_hints(Stream)
    for elem in stream:
        if not elem in props:
            return False
    return True