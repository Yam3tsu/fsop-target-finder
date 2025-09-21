from .constants import PARAMS_FILE, DEFAULT_LIBC, DEFAULT_LINKER, \
                        FIND_WFILE_OVERFLOW_DAEMON as DAEMON, \
                        BASE_ADDR_DAEMON as LIBC_DAEMON, debug_print, compile_target
import subprocess
import os
import re

RESULT_R = re.compile(r"^Offset: (0x[0-9a-fA-F]+)$")

def get_wfile_overflow(libc : str = DEFAULT_LIBC, ld : str = DEFAULT_LINKER):
    """
    This function should retrive the offset from the libc base address of the entry of
    _IO_wfile_overflow in the vtable of FILE streams. The function will return a list with the offsets
    of all the entries it founds.

    - libc -- The path of the libc to use. Offsets may depend on the libc version.
    - ld -- The dynamic loader to use. It's necessart that it is compatible with the given libc.
    """
    
    offsets = []
    libc_path = os.path.abspath(libc)
    ld_path = os.path.abspath(ld)
    compile_res = compile_target(libc_path, ld_path)
    debug_print(f"Compile res: {compile_res}")
    with open(PARAMS_FILE, "w") as f:
        f.write(f"Libc: {libc_path}\n")
        f.write(f"Linker: {ld_path}\n")
    
    try:
        output = subprocess.run(
            ["gdb", "-q", "--nx", "-ex", "set debuginfod enabled on", "-ex", f"source {LIBC_DAEMON}", "-ex", f"source {DAEMON}"],
            capture_output=True,
            timeout=3
            ).stdout.decode()
    except subprocess.TimeoutExpired as e:
        os.system("stty sane")          # Restore the broken terminal
        try:
            captured_err = e.stderr.decode()
        except:
            captured_err = ""
        captured_out = e.stdout.decode()
        debug_print(f"Capture before time out:\nstdout: {captured_out}\nstderr: {captured_err}")
        exit(1)
    
    debug_print(f"Output recived:\n{output}")
    for line in output.split("\n"):
        m = re.match(RESULT_R, line)
        if m != None:
            offsets.append(int(m.group(1)[2:], 16))
    return offsets