
class FuzzerStats:
    """
    Prints stats of the current fuzzer
    """

    def __init__(self,fuzzer):
        """
        proj = angr.Project
        cfg = proj.analyses.CFG()
        """
        self._fuzzer = fuzzer

    def setConsole(self,console):
        self._console = console

    def draw(self,height,width):

        # TODO: Check for console size before returning stuff
        fuzzer = self._fuzzer

        if not fuzzer.alive:
            return "Fuzzer is not running"

        
        # Fuzzer is alive, print out stats
        
        # afl_version

        table = PrettyTable([" ","bitmap","cycles","execs","pfavs","tfavs","crash","hang"])
        table.border = False # Border only takes up space!
        
        # Each fuzzer instance is a row
        for fuzzerName in sorted(fuzzer.stats):
            fuzzerInstance = fuzzer.stats[fuzzerName]
            
            table.add_row([
                fuzzerName,
                fuzzerInstance['bitmap_cvg'],
                fuzzerInstance['cycles_done'],
                fuzzerInstance['execs_done'],
                fuzzerInstance['pending_favs'],
                fuzzerInstance['paths_favored'],
                fuzzerInstance['unique_crashes'],
                fuzzerInstance['unique_hangs'],
            ])
        
        return str(table)
        
from prettytable import PrettyTable
from termcolor import colored
