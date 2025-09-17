#!/usr/bin/python3

import argparse
import json
import subprocess
import os
import re

INSTALLATION_PATH = "/home/pwnguy/Tools/fsop/fsop-target-finder"
DAEMON = f"{INSTALLATION_PATH}/gdb_daemon.py"
OFFSET_R = re.compile(r"^Offset: (0x[0-9a-f]+)$")
SYMBOL_R = re.compile(r"^Function: ([a-zA-Z_]+)$")
HEX_IN_JSON_R = re.compile(r'^(\s*"[a-zA-Z0-9_]+": )(0x[0-9a-zA-Z]+),?$')
JSON_CLOSE_R = re.compile(r"^\s*}\s*$")
PARAMS_FILE = f"{INSTALLATION_PATH}/param.txt"
CUSTOM_STREAMS_PATH = f"{INSTALLATION_PATH}/custom_streams/"
STD_STREAMS = ["stdin", "stdout", "stderr"]
DEBUG = False

FIND_TARGET_DESCRIPTION = '''
Given a libc function which act on file stream, this tool should retrive the offset of the vtable function
called. The goal is to make FILE struct exploitation easier by avoiding to dive into libc source code
'''

TARGET_HELP = '''The target function call passed as function(arg1, arg2, ...)
function: The target function
arg[number] Can be an hardcoded value or one of the following alias:
BUFFER[SIZE]    replace the argument with the address of a buffer allocated using malloc(SIZE)
BUFFER          alias for BUFFER[0x10]
STREAM          replace the argument with the address of the file stream

To get the vtable function called the tool will call the target function using the given template
'''

STREAM_HELP = f'''The FILE stream which will be passed to the target function call
The stream has to be passed as a json (you can obtain the ideal formatting by using json.dumps(dictionary) in python)
This json has to be an implementation of a specific interface.
You can get the interface using {os.path.basename(__file__)} --interface

It's possible to not include all the fields.
In that case the omitted fields will have the value of the stream generated with fopen(file_name, "rw")

Example:
{os.path.basename(__file__)} fwrite(BUFFER, 0x10, 0x1, STREAM) -s '{{"_flags": 0xfbad0000, "_IO_read_ptr": 0xdeadbeef}}'

If omitted it will be replaced with stderr

'''

STREAM_FILE_HELP = f'''The path of a file containing a json representing the FILE stream
The json sohuld be an implementation of a specific interface.
You can get the interface by using {os.path.basename(__file__)} --interface

'''

STD_HELP = '''This option allows to quickly use one of the 3 standard stream

'''

CUSTOM_HELP = f'''This option allows to use one of the premaid custom streams. 
These streams are located at {CUSTOM_STREAMS_PATH}.
An example of premade stream is the exit stream. This is a stream on which exit will call a function from the vtable.
To get more detail about the exit read the docs

'''

INTERFACE_HELP = f'''Get the interface of the object passed via --stream or --stream-file

'''

LIBC_HELP = '''Path to the libc used by the binary
If omitted the system libc will be used /lib/x86_64-linux-gnu/libc.so.6

'''

LINKER_HELP = '''Path to the dynamic loader used by the binary
If omitted the system loader will be used /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2

'''

DEBUG_HELP = '''Show the debug output. Each debug line is preceded by "[DEBUG]"

'''

HELP_HELP = '''Show this help message and exit

'''

INTERFACE = '''
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
'''

class ShowInterface(argparse.Action):
    def __call__(self, parser, namespace, values, option_string = None):
        print(INTERFACE)
        parser.exit()

def update_params(target : str, libc : str, linker : str, stream : dict):
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

def get_custom_choices():
    return os.listdir(f"{INSTALLATION_PATH}/custom_streams")

if __name__ == "__main__":

    # Argument parsing routine
    parser = argparse.ArgumentParser(description=FIND_TARGET_DESCRIPTION, formatter_class=argparse.RawTextHelpFormatter, add_help=False)
    parser.add_argument("-h", "--help", action="help", help=HELP_HELP)
    parser.add_argument("target", type=str, help=TARGET_HELP)
    parser.add_argument("-s", "--stream", type=json.loads, default=False, help=STREAM_HELP)
    parser.add_argument("-f", "--stream-file", type=argparse.FileType("r"), default=False, help=STREAM_FILE_HELP)
    parser.add_argument("-std", "--standard-stream", type=str, choices=["stdin", "stdout", "stderr"], default=False, help=STD_HELP)
    parser.add_argument("-custom", "--custom-stream", type=str, choices=get_custom_choices(), default=False, help=CUSTOM_HELP)
    parser.add_argument("--interface", nargs=0, action=ShowInterface, help=INTERFACE_HELP)
    parser.add_argument("--libc", type=str, default="/lib/x86_64-linux-gnu/libc.so.6", help=LIBC_HELP)
    parser.add_argument("--linker", type=str, default="/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", help=LINKER_HELP)
    parser.add_argument("-d", "--debug", action="store_true", default=False, help=DEBUG_HELP)

    args = parser.parse_args()
    target = args.target
    stream = args.stream
    std_stream = args.standard_stream
    libc = args.libc
    linker = args.linker
    DEBUG = args.debug

    if args.interface == True:
        print(INTERFACE)
        exit(0)

    if args.custom_stream != False:
        assert(stream == False)
        assert(std_stream == False)
        assert(args.stream_file == False)
        args.stream_file = open(CUSTOM_STREAMS_PATH + args.custom_stream, "r")

    if std_stream != False:
        assert(stream == False)
        stream = std_stream
    
    if args.stream_file != False:
        assert(stream == False)
        assert(std_stream == False)
        parsed = "{"
        lines : list = args.stream_file.readlines()
        # Removing empty lines
        while True:
            try:
                lines.remove("\n")
            except:
                break
        lines_number = len(lines)
        counter = 0
        for line in lines:
            if re.match(JSON_CLOSE_R, line) != None:
                break
            if counter == 0:
                line = line.replace("{", "")
            if counter == lines_number - 1:
                line = line.replace("}", "")
            counter += 1
            m = re.match(HEX_IN_JSON_R, line)
            if m != None:
                parsed += f"{m.group(1)}{int(m.group(2), 16)},"
            else:
                parsed += f"{line}"
        # We need to remove the last comma or json.loads will cry a river
        if m != None:
            to_remove = parsed.rfind(",")
            parsed = parsed[:to_remove] + parsed[to_remove+1:]
        parsed += "}"
        debug_print(f"Loading the parsed json:\n{parsed}")
        stream = json.loads(parsed)

    update_params(target, libc, linker, stream)

    # Run gdb
    try:
        out = subprocess.run(
            ["gdb", "-q", "--nx", "-ex", "set debuginfod enabled on", "-ex", f"source {DAEMON}"],
            capture_output=True,
            timeout=3
        ).stdout.decode()
    except subprocess.TimeoutExpired as e:
        captured = e.stdout.decode()
        os.system("stty sane")          # Restore the broken terminal
        debug_print(f"Capture before time out:\n{captured}")
        if "No vtable function hitted" in captured:
            print("The function called didn't hit any vtable function")
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
    
    print(f"Offset: {hex(offset)}\nSymbol: {symbol}")