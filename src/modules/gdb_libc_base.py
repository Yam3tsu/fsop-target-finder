import gdb
import re

LIBC_RE = re.compile(r"^(?:\s*0x[0-9a-fA-F]+){4}\s*[rwxp-]{4}\s*(?:\/.*)\/libc-(?:2|1)\.[0-9]{1,2}\.so$")

class GetBaseAddress(gdb.Command):

    setted = False
    libc_found = False

    def __init__(self):
        super().__init__("setbase", gdb.COMMAND_USER)
    

    def invoke(self, arg, from_tty):
        base_address = self.get_base()
        gdb.execute(f"set $base_address = (void*){hex(base_address)}")
        if GetBaseAddress.libc_found == False:
            libc = self.get_libc()
            if libc == -1:
                return
            gdb.execute(f"set $libc_base = (void*){hex(libc)}")
            GetBaseAddress.libc_found = True

    def get_base(self):
        try:
            maps = gdb.execute("info proc mappings", to_string=True)
        except:
            print("Process not started yet")
            return
        
        base = maps.split("\n")[4]
        base = base[base.find("0"):]
        base = base[:base.find(" ")]
        base = int(base, 16)
        return base

    def get_libc(self):
        try:
            maps = gdb.execute("info proc mappings", to_string=True)
        except:
            print("Process not started yet")
            return
        lines = maps.split("\n")[4:]
        for line in lines:
            print(re.match(LIBC_RE, line.strip()))
            print(line)
            if "libc.so.6" in line or re.match(LIBC_RE, line.strip()) != None:
                addr = line[line.find("0"):]
                addr = addr[:addr.find(" ")]
                addr = int(addr, 16)
                return addr
        return -1

GetBaseAddress()

def on_stop(event):
    if GetBaseAddress.setted == False or GetBaseAddress.libc_found == False:
        gdb.execute("setbase")
        GetBaseAddress.setted = True

gdb.events.stop.connect(on_stop)