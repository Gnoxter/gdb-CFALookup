import gdb
import os
import bisect

from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
from elftools.dwarf.descriptions import _REG_NAMES_x64

class FirstElementCompare(object):
    # bisect doesn't accept a key function, so we build the key into our sequence.
    def __init__(self, l):
        self.l = l
    def __len__(self):
        return len(self.l)
    def __getitem__(self, index):
        return self.l[index][0] 

def find_le(a, x):
    'Find rightmost value less than or equal to x'
    i = bisect.bisect_right(FirstElementCompare(a), x)
    if i:
        return i-1
    return None

class CFALookup:
    """ CFALookup allows to lookup CFA information for an address inside gdb by reading the sections directly from the binaries """
    def __init__(self):
        self.mapping = []
        
    def add_proc_map(self):
        mapping = gdb.execute("info proc map", to_string=True)
        mapping = mapping.split("\n")
        mapping = mapping[4:]

        for entry in mapping:
            entry = entry.split()
            if len(entry) < 5:
                continue
            if not os.path.isfile(entry[4]):
                continue
            self.add_file(int(entry[0], 16), int(entry[1], 16), entry[4])

    def add_file(self, start_addr, end_addr, filename):
        bisect.insort(self.mapping, (start_addr, {'start': start_addr, 'end': end_addr, 'objfile': filename, 'fdes': None}))

    def generate_FDE_table(self, filename):
        with open(filename, "rb") as f:
            elffile = ELFFile(f)
            elffile.has_dwarf_info()
            d = elffile.get_dwarf_info()
            table = [] 
            if d.has_EH_CFI():
                for entry in d.EH_CFI_entries():
                    if not isinstance(entry, FDE):
                        continue 
                    table.append((entry['initial_location'], entry))

            if d.has_CFI():
                for entry in d.CFI_entries():
                    if not isinstance(entry, FDE):
                        continue 
                    table.append((entry['initial_location'], entry))

            table.sort()
            return table

    def search_fde(self, fde, addr):
        last = {'cfa':None}
        for e in fde.get_decoded().table:
            pc = e['pc']
            if addr == pc:
                return e['cfa']
            if addr < pc:
                return last['cfa']

            last = e

        if addr >= last['pc'] and addr < fde['initial_location'] + fde['address_range']:
            return last['cfa']
        return None

    def lookup_cfa_force(self,  index, addr):
        mapping = self.mapping[index][1]
        index = find_le(mapping['fdes'], addr)

        if index == None:
            return None

        return self.search_fde(mapping['fdes'][index][1], addr)


    def lookup_force(self, addr):
        for index in range(0, len(self.mapping)):
            index = 0
            if not self.mapping[index][1]['fdes']:
                self.mapping[index][1]['fdes'] = self.generate_FDE_table(self.mapping[index][1]['objfile'])
            cfa = self.lookup_cfa_force(index, addr)
            if cfa:
                return cfa
        return None

    def lookup_cfa(self, map_index, addr):
        mapping = self.mapping[map_index][1]
        addr = addr-mapping['start']

        index = find_le(mapping['fdes'], addr)
        if index == None:
            return None

        fde = mapping['fdes'][index][1]
        if addr > fde['initial_location'] + fde['address_range']:
            print("Not in fde range")
            return None

        return self.search_fde(mapping['fdes'][index][1], addr)

    def lookup(self, addr, force = False):
        """ Returns give CFA element or None for the given addr. If force is set true it will search all files regardless of mapping"""
        if force:
            return self.lookup_force(addr)

        index = find_le(self.mapping, addr)
        if index == None:
            print("No suitable file found for 0x{:x}".format(addr))
            return None

        if addr > self.mapping[index][1]['end']:
            print("Between maps")
            return None

        if not self.mapping[index][1]['fdes']:
            self.mapping[index][1]['fdes'] = self.generate_FDE_table(self.mapping[index][1]['objfile'])

        return self.lookup_cfa(index, addr)

