import re
import json
from typing import TypedDict
import gdb

INSTALLATION_PATH = "/home/pwnguy/Tools/fsop/fsop_target_finder"
EXE_FILENAME = f"{INSTALLATION_PATH}/target"
PARAMS_FILE = f"{INSTALLATION_PATH}/param.txt"

# The following regex should parse the parameters from PARAMS_FILE
LINKER_R = re.compile(r"^Libc: ([a-zA-Z0-9_\.\/-]+)$")
LIBC_R = re.compile(r"^Linker: ([a-zA-Z0-9_\.\/-]+)$")
STREAM_R = re.compile(r"^Stream: (.+)$")
GDB_CALL_R = re.compile(r"^\$[0-9]+ = \(FILE \*\) (0x[0-9a-f]+)$")

VTABLES_NUM = 17
JUMP_T_SIZE = 0xa8
VTABLE_LEN = VTABLES_NUM * JUMP_T_SIZE
STD_STREAMS = ["stdin", "stdout", "stderr"]

STOP_AT_FIRST = False
DEBUG = True
INTERACTIVE = False
STRONG_CHECK = False

# Stream interface
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


class Vtable_Breakpoint(gdb.Breakpoint):
    
    def __init__(self, spec, symbol : str = None, offset : int = None, **kwargs):
        super().__init__(spec, **kwargs)
        self.addr = int(spec[3:], 16)
        if symbol == None:
            f_addr = gdb.Value(self.addr).cast(gdb.lookup_type("long").pointer()).dereference()
            block = gdb.block_for_pc(f_addr)
            self.symbol = block.function.print_name
        else:
            self.symbol = symbol
        self.offset = offset
    
    def stop(self):
        print(f"Function: {self.symbol}")
        print(f"Offset: {hex(self.offset)}")
        gdb.execute("quit", to_string=True)
        return True

def check_stream(stream : dict):
    try:
        Stream(**stream)
        return True
    except:
        return False

def debug_print(s : str):
    if DEBUG == True:
        for line in s.split("\n"):
            print(f"[DAEMON_DEBUG] {line}")

def parse_stream():
    if STREAM == False:
        gdb.execute("set $stream = stderr")
    elif STREAM in STD_STREAMS:
        gdb.execute(f"set $stream = {STREAM}")
    elif check_stream(Stream) or STRONG_CHECK == False:        
        # Parse the new stream address
        gdb_stream = gdb.execute(f"call fopen(\"{PARAMS_FILE}\", \"rw\")", to_string=True)
        m = re.match(GDB_CALL_R, gdb_stream)
        if m == None:
            print("There was a problem with the fopen call!")
            exit(1)
        gdb_stream_address = int(m.group(1), 16)
        gdb.execute(f"set $stream = (FILE *){hex(gdb_stream_address)}")

        # Overwrite the new file stream with the one given in input
        for element in STREAM:
            if element == "_unused2":
                unused_list = "{"
                for elem in STREAM[element]:
                    unused_list += f"{elem}, "
                unused_list = unused_list[:-2] + "}"
                gdb.execute(f"set (char [20])$stream->_unused2 = {unused_list}")
            elif element == "vtable":
                gdb.execute(f"set ((struct _IO_FILE_plus *)$stream)->{element} = {hex(STREAM[element])}")
            else:
                gdb.execute(f"set $stream->{element} = {hex(STREAM[element])}")
    else:
        print("Invalid stream!")
        gdb.execute("quit", to_string=True)
        

# Parse parameters from param file
with open(PARAMS_FILE, "r") as f:
    lines = f.readlines()
for line in lines:
    debug_print(f"Parsing {line}")
    m = re.match(LINKER_R, line)
    if m != None:
        LINKER = m.group(1)
        continue
    m = re.match(LIBC_R, line)
    if m != None:
        LIBC = m.group(1)
        continue
    m = re.match(STREAM_R, line)
    if m != None:
        value = m.group(1)
        if value == "False":
            STREAM = "stderr"
        elif value in STD_STREAMS:
            STREAM = value
        else:
            STREAM = json.loads(value)
        

assert("LINKER" in globals())
assert("LIBC" in globals())
# assert("VTABLE" in globals())
assert("STREAM" in globals())

INIT_SCRIPT = f'''
    file {EXE_FILENAME}
    b main
    run {LINKER} --library-path {LIBC} {EXE_FILENAME}
'''

gdb.execute(INIT_SCRIPT, to_string=True)
parse_stream()
gdb.execute("set $vtable = (long)((struct _IO_FILE_plus *)$stream)->vtable")
vtable = gdb.parse_and_eval("$vtable")

vtable_start = gdb.parse_and_eval("(long)__io_vtables")
vtable_end = vtable_start + VTABLE_LEN
vtable_stream = gdb.parse_and_eval("$vtable")

for addr in range(vtable_start, vtable_end, 0x8):
    f_addr = gdb.Value(addr).cast(gdb.lookup_type("long").pointer()).dereference()
    block = gdb.block_for_pc(f_addr)
    if block == None:
        continue
    if block.function:
        symbol = block.function.print_name
        if symbol == "_IO_wfile_overflow" or symbol == "__GI__IO_wfile_overflow":
            print(f"Offset: {hex(addr - vtable)}")
            if STOP_AT_FIRST == True and INTERACTIVE == False:
                gdb.execute("quit", to_string = True)

if INTERACTIVE == False:
    gdb.execute("quit", to_string = True)