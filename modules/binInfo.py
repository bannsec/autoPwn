
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

    def setConsole(self,console):
        self._console = console

    def draw(self,height,width):

        # TODO: Check for console size before returning stuff

        if self._table:
            return str(table)

        table = PrettyTable(["Binary","Arch","Type","RELRO","NX","PIC","Fortify","ASAN","MSAN","UBSAN","AFL","Build"])
        table.border = False # Border only takes up space!

        # Build-id
        state = self._proj.factory.blank_state()
        section = self._proj.loader.main_bin.sections_map['.note.gnu.build-id']
        buildID = hex(state.se.any_int(state.memory.load(section.vaddr+16,20)))[2:].rstrip("L")

        table.add_row([
            self._proj.loader.main_bin.binary,
            self._proj.loader.main_bin.arch.name,
            self._proj.loader.main_bin.filetype,
            self._proj.loader.main_bin.rela_type,
            not self._proj.loader.main_bin.execstack,
            self._proj.loader.main_bin.pic,
            "Enabled" if any(self._cfg.functions[func].name.endswith("_chk") for func in self._cfg.functions) else "Disabled",
            "Enabled" if any(self._cfg.functions[func].name.startswith("__asan_") for func in self._cfg.functions) else "Disabled",
            "Enabled" if any(self._cfg.functions[func].name.startswith("__msan_") for func in self._cfg.functions) else "Disabled",
            "Enabled" if any(self._cfg.functions[func].name.startswith("__ubsan_'") for func in self._cfg.functions) else "Disabled",
            "Enabled" if any(self._cfg.functions[func].name.startswith("__afl_") for func in self._cfg.functions) else "Disabled",
            buildID,
            ])

        # Cache the results
        self._table = table

        return str(table)
        
        """
        # If we're in too small of an area to actually draw, just type
        if height < 7 or width < 117:
            return "autoPwn -- {0}".format(url)

        else:
            return banner
        """
from prettytable import PrettyTable
