#!/usr/bin/python3

from modules.find_wfile_overflow_module import get_wfile_overflow
from modules.constants import DEFAULT_LIBC, DEFAULT_LINKER
import argparse

DESCRIPTION = '''This tool should be able to find the offset, respect to libc base address, of the location of
_IO_wfile_overflow in the vtable region. The tool will return a list because this function is located at 3 different entries

'''

LIBC_HELP = f'''The libc to use.
The offset can depend on the libc version.
If omitted the tool will use the libc located at {DEFAULT_LIBC}

'''

LINKER_HELP = f'''The dynamic linker to use.
It's sufficient that the linker can link the selected libc.
If omitted the tool will use the linker located at {DEFAULT_LINKER}

'''

PYTHON_LIST_HELP = f'''When this flag is active, the output will be in the form of a python list.

'''

HELP_HELP = '''Show this help message and exit

'''

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=DESCRIPTION, formatter_class=argparse.RawTextHelpFormatter, add_help=False)
    parser.add_argument("-h", "--help", action="help", help=HELP_HELP)
    parser.add_argument("--libc", type=str, default=DEFAULT_LIBC, help=LIBC_HELP)
    parser.add_argument("-ld", "--dynamic-linker", type=str, default=DEFAULT_LINKER, help=LINKER_HELP)
    parser.add_argument("--python-list", action="store_true", help=PYTHON_LIST_HELP)

    args = parser.parse_args()
    libc = args.libc
    linker = args.dynamic_linker
    offsets = get_wfile_overflow(libc=libc, ld=linker)
    if args.python_list == True:
        print(offsets)
    else:
        counter = 1
        for offset in offsets:
            print(f"Offset {counter}: {hex(offset)}")
            counter += 1