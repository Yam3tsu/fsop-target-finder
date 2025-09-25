import re
import json
import sys
import gdb

INSTALLATION_PATH = "/home/pwnguy/Tools/fsop/fsop_target_finder"

sys.path.append(f"{INSTALLATION_PATH}/src/modules")
from constants import PARAMS_FILE, STRONG_CHECK, DEBUG, INTERACTIVE, \
                      STD_STREAMS, VTABLE_LEN, INIT_SCRIPT, check_stream, \
                      gdb_debug_print as debug_print

# The following regex should parse the parameters from PARAMS_FILE
LINKER_R = re.compile(r"^Libc: ([a-zA-Z0-9_\.\/-]+)$")
LIBC_R = re.compile(r"^Linker: ([a-zA-Z0-9_\.\/-]+)$")
STREAM_R = re.compile(r"^Stream: (.+)$")
CALL_R = re.compile(r"^Call: (.+)\((.*)\)$")

# This regex should parse the output of gdb.execute("call ...")
GDB_CALL_R = re.compile(r"^\$[0-9]+ = \(FILE \*\) (0x[0-9a-f]+)$")

# The following regex are used to parse CALL
PARSE_CALL_ARGUMENTS_R = re.compile(r"\s*(BUFFER(?:\[(?:[0-9]+|0x[0-9a-fA-F]+)\])?|STREAM|0x[0-9a-fA-F]+|\d+)\s*,?")
DEFINED_BUFFER_R = re.compile(r"^BUFFER\[(0x[0-9a-fA-F]+|\d+)\]$")


class Vtable_Breakpoint(gdb.Breakpoint):
    """
    This breakpoint is setted on vtable entries.\n
    When hitted it print the offset of the entry and then execute quit on gdb
    """
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

def parse_stream():
    """
    This function should parse the STREAM and then include it in gdb.\n
    To include in gdb it will call fopen("param.txt", "rw"), where param is just a placeholder txt file.\n
    A referement to the stream will be stored in the gdb $stream variable
    """

    if STREAM == False:
        gdb.execute("set $stream = stderr")
    elif STREAM in STD_STREAMS:
        gdb.execute(f"set $stream = {STREAM}")
    elif check_stream(STREAM) or STRONG_CHECK == False:        
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
    
def parse_call(function : str, arguments : str):
    """
    This function should take in input a libc function and its arguments.\n
    The arguments can be hardcoded integer, the literal "BUFFER", a string of the type
    BUFFER[Size] or the literal "STREAM".\n
    It will create a gdb script which will allocate the BUFFERs and call the function, replacing
    BUFFERs with their referement, STREAM with a referement to the stream and the other arguments will be
    left unchanged.\n
    BUFFERs will be allocated by "malloc(Size)", if Size is not given it will be allocated a 0x10 bytes buffer.
    """

    allocation_script = ""
    allocation_counter = 0
    call = f"call {function}("
    debug_print(f"Arguments: {arguments}")
    m = re.findall(PARSE_CALL_ARGUMENTS_R, arguments)
    debug_print(f"Parsed args: {m}")
    if len(m) == 0:
        return call + ")"
    for arg in m:
        if arg == "STREAM":
            call += "$stream, "
        elif arg == "BUFFER":
            allocation_script += f"set $buffer{allocation_counter} = malloc(0x10)\n"
            call += f"$buffer{allocation_counter}, "
            allocation_counter += 1
        elif "BUFFER" in arg:
            size = re.match(DEFINED_BUFFER_R, arg).group(1)
            if "0x" in size:
                size = int(size[2:], 16)
            else:
                size = int(size)
            allocation_script += f"set $buffer{allocation_counter} = malloc({size})\n"
            call += f"$buffer{allocation_counter}, "
            allocation_counter += 1
        else:
            call += f"{arg}, "
    call = call[:-2] + ")"
    debug_print(f"Parsed script: {allocation_script + call}")
    return allocation_script + call
        

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
        if m.group(1) == "False":
            STREAM = False
        elif m.group(1) in STD_STREAMS:
            STREAM = m.group(1)
        else:
            STREAM = json.loads(m.group(1))
    m = re.match(CALL_R, line)
    if m != None:
        CALL = m.group(1)
        CALL_ARGS = m.group(2)

debug_print(f"Call: {CALL}")
assert("LINKER" in globals())
assert("LIBC" in globals())
assert("STREAM" in globals())

gdb.execute(INIT_SCRIPT, to_string=True)

parse_stream()

debug_print(f"Using the stream: {gdb.parse_and_eval("$stream")}")

call_script = parse_call(m.group(1), m.group(2))

# Some libc have the symbol __io_vtables which point to the start of the vtable area.
# Others have the symbols __start___libc_IO_vtables and __stop___libc_IO_vtables
try:
    vtable_start = gdb.parse_and_eval("(long)__io_vtables")
    vtable_end = vtable_start + VTABLE_LEN
except:
    vtable_start = gdb.parse_and_eval("(long)__start___libc_IO_vtables")
    vtable_end = gdb.parse_and_eval("(long)__stop___libc_IO_vtables")

vtable_stream = gdb.parse_and_eval("(long)((struct _IO_FILE_plus *)$stream)->vtable")

for addr in range(vtable_stream, vtable_end, 0x8):
    f_addr = gdb.Value(addr).cast(gdb.lookup_type("long").pointer()).dereference()
    block = gdb.block_for_pc(f_addr)
    if block == None:
        continue
    if block.function:
        symbol = block.function.print_name
        Vtable_Breakpoint(f"*{hex(f_addr)}", symbol=symbol, offset=(addr - vtable_stream), internal=True)

debug_print(f"Executing the script:\n{call_script}")

if INTERACTIVE == False:
    gdb.execute(call_script)
    print("Error: No vtable function hitted")