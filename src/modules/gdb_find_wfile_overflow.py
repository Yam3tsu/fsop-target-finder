import re
import sys
import gdb

INSTALLATION_PATH = "/home/pwnguy/Tools/fsop/fsop_target_finder"
sys.path.append(f"{INSTALLATION_PATH}/src/modules")

from constants import EXE_FILENAME, PARAMS_FILE, DEBUG, INTERACTIVE, VTABLE_LEN, \
                      INIT_SCRIPT, gdb_debug_print as debug_print

# The following regex should parse the parameters from PARAMS_FILE
LIBC_R = re.compile(r"^Libc: ([a-zA-Z0-9_\.\/-]+)$")
LINKER_R = re.compile(r"^Linker: ([a-zA-Z0-9_\.\/-]+)$")

STOP_AT_FIRST = False

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
        

assert("LINKER" in globals())
assert("LIBC" in globals())

gdb.execute(INIT_SCRIPT, to_string=True)
gdb.execute("setbase")
libc_base = gdb.parse_and_eval("(long)$libc_base")
debug_print(f"Libc base: {hex(libc_base)}")

try:
    vtable_start = gdb.parse_and_eval("(long)__io_vtables")
    vtable_end = vtable_start + VTABLE_LEN
except:
    vtable_start = gdb.parse_and_eval("(long)__start___libc_IO_vtables")
    vtable_end = gdb.parse_and_eval("(long)__stop___libc_IO_vtables")

debug_print(f"Vtable size: {hex(vtable_end - vtable_start)}")
vtable_stream = gdb.parse_and_eval("$vtable")

for addr in range(vtable_start, vtable_end, 0x8):
    f_addr = gdb.Value(addr).cast(gdb.lookup_type("long").pointer()).dereference()
    block = gdb.block_for_pc(f_addr)
    if block == None:
        continue
    if block.function:
        symbol = block.function.print_name
        if symbol == "_IO_wfile_overflow" or symbol == "__GI__IO_wfile_overflow":
            print(f"Offset: {hex(addr - libc_base)}")
            if STOP_AT_FIRST == True and INTERACTIVE == False:
                gdb.execute("quit", to_string = True)

if INTERACTIVE == False:
    gdb.execute("quit", to_string = True)