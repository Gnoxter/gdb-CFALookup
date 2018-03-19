import gdb
import sys

directory, filename = path.split(__file__)
directory       = path.expanduser(directory)
directory       = path.abspath(directory)

sys.path.append(directory)

from cfa_lookup import CFALookup

class CFAInfo(gdb.Command):
    """Print CFARule, showcase for the CFALookup class:
cfa_info <addr>       - Lookup by using memory to to file mapping
cfa_info force <addr> - Search all files (for core dumps)"""
    def __init__(self):
        super(CFAInfo, self).__init__ ("cfa_info", gdb.COMMAND_USER)
        self.cfa = CFALookup()
        self.initalized = False

    def invoke(self, arg, from_tty):
        force = False

        if not self.initalized:
            self.cfa.add_proc_map()

        addr = arg.split()
        if len(addr) == 2 and addr[0] == "force":
            addr = addr[1]
            force = True
        elif len(addr) == 1:
            addr = addr[0]


        try:
            addr = int(addr, 16)
        except ValueError:
            print("Invalid adress")
            return

        cfa = self.cfa.lookup(addr, force)
        if cfa:
            print(cfa)

CFAInfo()
