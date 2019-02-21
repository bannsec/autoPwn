def n32
stepi
x/10i $eip
i r
end

def n64
stepi
x/10i $rip
i r
end

set disassembly-flavor intel
set follow-fork-mode child

layout split
layout regs

python
import re
import os
def breakpoint_pie(file_name, offset):
    """Sets breakpoint at offset in file based on currently loaded address."""
    map = gdb.execute("info proc map",True,True)
    map = map.split("\n")
    assert type(file_name) is str, "Unknown type for file_name of {}".format(type(file_name))
    if type(offset) is str:
        try:
            offset = int(gdb.execute("p/x &{}".format(offset),True,True).split(" = ")[1],16)
        except:
            print("[-] Couldn't resolve offset symbol '{}'".format(offset))
            return
    for line in map:
        try:
            lower, upper, size, obj_offset, obj_name = re.findall("\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$",line)[0]
            lower = int(lower,16)
            upper = int(upper,16)
            size = int(size,16)
            obj_offset = int(obj_offset,16)
            if os.path.basename(obj_name) == file_name:
                breakpoint = lower + offset
                print("[+] Setting breakpoint: " + hex(breakpoint))
                _ = gdb.execute("break *" + hex(breakpoint),True,True)
                break
        except:
            pass
    else:
        print("[-] Couldn't find file...")
end

define breakpoint_pie
    python breakpoint_pie($arg0, $arg1)
end
python

activate_this_file = "/home/angr/.virtualenvs/angr/bin/activate_this.py"
exec(open(activate_this_file,"r").read(), dict(__file__=activate_this_file))

import angrgdb.commands

end
