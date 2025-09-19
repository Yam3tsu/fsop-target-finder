import argparse
import json
import subprocess
import os
import re
from .constants import VTABLE_OFFSET_DAEMON as DAEMON, DEBUG, STD_STREAMS, DEFAULT_LIBC, DEFAULT_LINKER, INSTALLATION_PATH, \
                      PARAMS_FILE, get_custom_streams as get_custom_choices, CUSTOM_STREAMS_PATH, STD_STREAMS


OFFSET_R = re.compile(r"^Offset: (0x[0-9a-f]+)$")
SYMBOL_R = re.compile(r"^Function: ([a-zA-Z_]+)$")
HEX_IN_JSON_R = re.compile(r'^(\s*"[a-zA-Z0-9_]+": )(0x[0-9a-zA-Z]+)(,?)$')
JSON_CLOSE_R = re.compile(r"^\s*}\s*$")

class VtableFunctionNotFound(Exception):
    def __init__(self):
        super().__init__("Error: vtable function not found")

def update_params(target : str, libc : str, linker : str, stream : dict | str | bool):
    with open(PARAMS_FILE, "w") as f:
        f.write(f"Libc: {libc}\n")
        f.write(f"Linker: {linker}\n")
        if stream == False or stream in STD_STREAMS:
            f.write(f"Stream: {stream}\n")
        else:
            f.write(f"Stream: {json.dumps(stream)}\n")
        f.write(f"Call: {target}")

def debug_print(s : str):
    if DEBUG == True:
        for line in s.split("\n"):
            print(f"[DEBUG] {line}")

def parse_json(s : str):
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
        get_symbol : bool = False):
    if stream in get_custom_choices():
        with open(CUSTOM_STREAMS_PATH + "/" + stream) as f:
            stream = parse_json(f.read())
    update_params(target, libc, linker, stream)

    # Run gdb
    try:
        out = subprocess.run(
            ["gdb", "-q", "--nx", "-ex", "set debuginfod enabled on", "-ex", f"source {DAEMON}"],
            capture_output=True,
            timeout=3
        ).stdout.decode()
    except subprocess.TimeoutExpired as e:
        captured_err = e.stderr.decode()
        captured_out = e.stdout.decode()
        os.system("stty sane")          # Restore the broken terminal
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
            offset = int(m.group(1), 16)
            continue
        m = re.match(SYMBOL_R, line)
        if m != None:
            symbol = m.group(1)
    
    if get_symbol == True:
        return offset, symbol
    else:
        return offset