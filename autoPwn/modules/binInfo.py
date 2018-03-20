
class BinInfo:
    """
    Prints out a table of information about the current binary.
    """

    def __init__(self,proj,cfg):
        """
        proj = angr.Project
        cfg = proj.analyses.CFG()
        """
        self._proj = proj
        self._cfg = cfg
        self._table = None

        # Draw ourselves to init.
        # TODO: This should probably just be its own method
        self.draw(100,100)

    def setConsole(self,console):
        self._console = console

    def draw(self,height,width):

        # TODO: Check for console size before returning stuff

        # Use cached results for better performance
        if self._table:
            return str(self._table)

        table = PrettyTable(["Binary","Arch","Type","RELRO","NX","Canary","PIC","Fortify"])
        table.border = False # Border only takes up space!
        row = []
        
        # Binary
        row.append(self._proj.loader.main_bin.binary)

        # Arch
        row.append(self._proj.loader.main_bin.arch.name)
        
        # File Type
        row.append(type(self._proj.loader.main_bin).__name__)

        # RELRO (need to get this into CLE proper..)
        if 'DT_BIND_NOW' in self._proj.loader.main_bin._dynamic:
            self.relro = "full"
            row.append(colored("Full","green"))

        elif any("GNU_RELRO" in segment.header.p_type for segment in self._proj.loader.main_bin.reader.iter_segments()):
            self.relro = "partial"
            row.append(colored("Partial","yellow"))

        else:
            self.relro = "none"
            row.append(colored("None","red"))

        # NX
        if self._proj.loader.main_bin.execstack:
            self.nx = False
            row.append(colored("Disabled","red"))
        else:
            self.nx = True
            row.append(colored("Enabled","green"))

        # Canary
        if self._proj.loader.main_bin.get_symbol("__stack_chk_fail"):
            self.canary = True
            row.append(colored("Enabled","green"))
        else:
            self.canary = False
            row.append(colored("Disabled","red"))

        # PIC
        if self._proj.loader.main_bin.pic:
            self.pic = True
            row.append(colored("Enabled","green"))
        else:
            self.pic = False
            row.append(colored("Disabled","red"))

        # Fortify
        if any(self._cfg.functions[func].name.endswith("_chk") for func in self._cfg.functions):
            self.fortify = True
            row.append(colored("Enabled","green"))
        else:
            self.fortify = False
            row.append(colored("Disabled","red"))

        # ASAN
        if any(self._cfg.functions[func].name.startswith("__asan_") for func in self._cfg.functions):
            self.asan = True
            table.add_column("ASAN","")
            row.append(colored("Enabled","yellow"))

        else:
            self.asan = False

        # MSAN
        if any(self._cfg.functions[func].name.startswith("__msan_") for func in self._cfg.functions):
            self.msan = True
            table.add_column("MSAN","")
            row.append(colored("Enabled","yellow"))

        else:
            self.msan = False

        # UBSAN
        if any(self._cfg.functions[func].name.startswith("__ubsan_'") for func in self._cfg.functions):
            self.ubsan = True
            table.add_column("UBSAN","")
            row.append(colored("Enabled","yellow"))

        else:
            self.ubsan = False

        # AFL
        if any(self._cfg.functions[func].name.startswith("__afl_") for func in self._cfg.functions):
            self.afl = True
            table.add_column("AFL","")
            row.append(colored("Enabled","yellow"))

        else:
            self.afl = False

        # UPX
        offset = self._proj.loader.main_bin.binary_stream.tell()
        self._proj.loader.main_bin.binary_stream.seek(0)
        if "UPX!" in self._proj.loader.main_bin.binary_stream.read():
            self.packer = "UPX"
            table.add_column("Packer","")
            row.append(colored("UPX","red"))

        else:
            self.packer = None
        
        self._proj.loader.main_bin.binary_stream.seek(offset)

        # Build-id -- Disabling for now... it just takes up space and not sure why i care.
        #state = self._proj.factory.blank_state()
        #section = self._proj.loader.main_bin.sections_map['.note.gnu.build-id']
        #buildID = hex(state.se.any_int(state.memory.load(section.vaddr+16,20)))[2:].rstrip("L")
        #table.add_column("Build","")
        #row.append(buildID)

        table.add_row(row)

        # Cache the results
        self._table = table

        return str(table)
        
from prettytable import PrettyTable
from termcolor import colored
