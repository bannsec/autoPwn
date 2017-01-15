
class FuzzerStats:
    """
    Prints stats of the current fuzzer
    """

    def __init__(self,queues):
        """
        proj = angr.Project
        cfg = proj.analyses.CFG()
        """
        self._queues = queues
        self.drilling = False # Hack for now...
        self._me = 'fuzzstats'

    def setConsole(self,console):
        self._console = console

    def _fuzzer_alive(self):
        fuzzer = self._queues['engine']
        
        fuzzer.put(['fuzzer_alive',self._me])
        
        return self._queues[self._me].get()

    def _driller_alive(self):
        fuzzer = self._queues['engine']
        
        fuzzer.put(['driller_alive',self._me])
        
        return self._queues[self._me].get()

    def _fuzzer_stats(self):
        fuzzer = self._queues['engine']
        
        fuzzer.put(['fuzzer_stats',self._me])
        
        return self._queues[self._me].get()

    def draw(self,height,width):

        # TODO: Check for console size before returning stuff
        fuzzer = self._queues['engine']
        
        alive = self._fuzzer_alive()
        drilling = self._driller_alive()

        if not alive and not drilling:
            return "Not running"

        if not alive and drilling:
            return "Drilling in progress..."
        
        # Fuzzer is alive, print out stats
        
        # afl_version

        table = PrettyTable([" ","bitmap","cycles","execs","pfavs","tfavs","crash","hang"])
        table.border = False # Border only takes up space!

        fuzzer_stats = self._fuzzer_stats()
        
        # Each fuzzer instance is a row
        for fuzzerName in sorted(fuzzer_stats):
            fuzzerInstance = fuzzer_stats[fuzzerName]
            
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
