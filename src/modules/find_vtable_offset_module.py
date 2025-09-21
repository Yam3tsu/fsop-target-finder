import argparse
import json
import subprocess
import os
import re
from .constants import VTABLE_OFFSET_DAEMON as DAEMON, DEBUG, STD_STREAMS, DEFAULT_LIBC, DEFAULT_LINKER, \
                       PARAMS_FILE, get_custom_streams as get_custom_choices, CUSTOM_STREAMS_PATH, \
                       STD_STREAMS, debug_print, compile_target


OFFSET_R = re.compile(r"^Offset: (-?0x[0-9a-f]+)$")
SYMBOL_R = re.compile(r"^Function: ([a-zA-Z_]+)$")
HEX_IN_JSON_R = re.compile(r'^(\s*"[a-zA-Z0-9_]+": )(0x[0-9a-zA-Z]+)(,?)$')
JSON_CLOSE_R = re.compile(r"^\s*}\s*$")

class VtableFunctionNotFound(Exception):
    def __init__(self):
        super().__init__("Error: vtable function not found")

def update_params(target : str, libc : str, linker : str, stream : dict | str | bool):
    """
    This function should write on PARAMS_FILE the parameters given.\n
    That file is used to comunicate with the gdb python scripts.
    """
    with open(PARAMS_FILE, "w") as f:
        f.write(f"Libc: {libc}\n")
        f.write(f"Linker: {linker}\n")
        if stream == False or stream in STD_STREAMS:
            f.write(f"Stream: {stream}\n")
        else:
            f.write(f"Stream: {json.dumps(stream)}\n")
        f.write(f"Call: {target}")

def parse_json(s : str) -> dict:
    """
    This function should parse a json replacing hex numbers with decimal ones.\n
    It's necessary becouse json.loads() can't parse hex numbers.
    """
    parsed = ""
    for line in s.split("\n"):
        line = line.strip("\n")
        m = re.match(HEX_IN_JSON_R, line)
        if m != None:
            parsed += m.group(1) + str(int(m.group(2)[2:], 16)) + m.group(3) + "\n"
        else:
            parsed += line + "\n"
    parsed = parsed[:-1]
    debug_print(f"Parsed json:\n{parsed}")
    return json.loads(parsed)

def get_offset(
        target : str,
        libc : str = DEFAULT_LIBC,
        linker : str = DEFAULT_LINKER,
        stream : bool | str | dict = False,
        get_symbol : bool = False) -> int | tuple[int, str]:
    """
    This function should retrive the offset of the vtable entry called when the call specified in target
    is done.

    - target -- The function call to analyze. It comes in the format: function(param1, param2, ...)
    params can be given as hardcoded integer, the literal "STREAM", the literal "BUFFER", or
    a string of the type "BUFFER[Size]", where Size is an integer. The call that will be inspected
    will be a call to the specified function where the literal "STREAM" will be replaced with a
    referement to the stream, the strings "BUFFER[Size]" will be replaced with referement to buffers
    allocated by malloc(Size), the literal "BUFFER" will be treated as "BUFFER[0x10]", and the hardcoded
    parameters will be left unchanged.

    - libc -- The path of the libc to use. Be carefull, offset may change between different libc
    versions

    - linker -- The dynamic linker to use. It has to be compatible with the libc given

    - stream -- It indicates the stream to pass at the function when the keyword "STREAM" is used.
    It can be a standard stream ["stdout" | "stderr" | "stdin"], or the name of a custom stream or
    a dict. Custom streams can be found in the installation folder of this library.
    Dict must implements properties which can be found in the Stream interface (it can be found in
    constants.py, located in src/modules in the installation folder of this library). It's not necessary
    that the dict implements all the properties, but it can't implement properties which are not in the
    interface. If omitted stream will be treated as "stderr"

    - get_symbol -- If True the function will return a tuple (offset, symbol), if it's False
    it will return just the offset
    """

    if stream in get_custom_choices():
        with open(CUSTOM_STREAMS_PATH + "/" + stream) as f:
            stream = parse_json(f.read())
    
    libc = os.path.abspath(libc)
    linker = os.path.abspath(linker)
    debug_print(f"Libc: {libc}")
    debug_print(f"Linker: {linker}")
    compile_target(libc, linker)
    update_params(target, libc, linker, stream)
    
    # Run gdb
    try:
        out = subprocess.run(
            ["gdb", "-q", "--nx", "-ex", "set debuginfod enabled on", "-ex", f"source {DAEMON}"],
            capture_output=True,
            timeout=3
        ).stdout.decode()
    except subprocess.TimeoutExpired as e:
        os.system("stty sane")          # Restore the broken terminal
        captured_err = e.stderr.decode()
        captured_out = e.stdout.decode()
        debug_print(f"Capture before time out:\nstdout: {captured_out}\nstderr: {captured_err}")
        if "No vtable function hitted" in captured_out:
            raise VtableFunctionNotFound()
        else:
            print("An error occured during the execution of gdb!")
            exit(1)
    
    debug_print(f"Output of gdb daemon:\n{out}")

    for line in out.split("\n"):
        m = re.match(OFFSET_R, line)
        if m != None:
            offset = m.group(1)
            if offset[0] == "-":
                offset = -int(offset[3:], 16)
            else:
                offset = int(m.group(1), 16)
            continue
        m = re.match(SYMBOL_R, line)
        if m != None:
            symbol = m.group(1)
    
    if get_symbol == True:
        return offset, symbol
    else:
        return offset