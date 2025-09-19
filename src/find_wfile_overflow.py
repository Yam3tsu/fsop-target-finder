from constants import INSTALLATION_PATH, PARAMS_FILE, DEFAULT_LIBC, DEFAULT_LINKER, \
                      get_custom_streams, CUSTOM_STREAMS_PATH, FIND_WFILE_OVERFLOW_DAEMON as DAEMON
import subprocess
import re
import json

RESULT_R = re.compile(r"^Offset: (0x[0-9a-fA-F]+)$")

def get_wfile_overflow(stream : str | dict, libc : str = DEFAULT_LIBC, ld : str = DEFAULT_LINKER):
    offsets = []

    with open(PARAMS_FILE, "w") as f:
        f.write(f"Libc: {libc}\n")
        f.write(f"Linker: {ld}\n")
        if stream in get_custom_streams():
            with open(f"{CUSTOM_STREAMS_PATH}{stream}", "r") as c:
                stream = json.loads(c.read())
        f.write(f"Stream: {json.dumps(stream)}")
    
    output = subprocess.run(
        ["gdb", "-q", "--nx", "-ex", "set debuginfod enabled on", "-ex", f"source {DAEMON}"],
        capture_output=True
        ).stdout.decode()
    for line in output.split("\n"):
        m = re.match(RESULT_R, line)
        if m != None:
            offsets.append(int(m.group(1)[2:], 16))
    return offsets


if __name__ == "__main__":
    print(get_wfile_overflow("stderr"))