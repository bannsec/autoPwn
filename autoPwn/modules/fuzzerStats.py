
from .. import Config as GlobalConfig

class FuzzerStats:
    """
    Prints stats of the current fuzzer
    """

    def __init__(self):
        """
        proj = angr.Project
        cfg = proj.analyses.CFG()
        """
        self.drilling = False # Hack for now...
        self._me = 'fuzzstats'
        self._s = "Not running"

    def setConsole(self,console):
        self._console = console

    def _fuzzer_alive(self):
        fuzzer = GlobalConfig.queues['fuzzer']
        
        fuzzer.put({
            'command': 'alive',
            'replyto': self._me
        })
        
        return GlobalConfig.queues[self._me].get()

    def _driller_alive(self):
        fuzzer = GlobalConfig.queues['driller']
        
        fuzzer.put({
            'command': 'alive',
            'replyto': self._me
        })
        
        return GlobalConfig.queues[self._me].get()

    def _fuzzer_stats(self):
        fuzzer = GlobalConfig.queues['fuzzer']
        
        fuzzer.put({
            'command': 'stats',
            'replyto': self._me
        })
        
        return GlobalConfig.queues[self._me].get()

    def draw(self,height,width):

        # TODO: Check for console size before returning stuff
        return self._s
        

    def preDraw(self):
        """Predrawing so that we don't have that lag time when actually drawing"""

        fuzzer = GlobalConfig.queues['fuzzer']
        
        alive = self._fuzzer_alive()
        drilling = self._driller_alive()

        if not alive and not drilling:
            self._s = "Not running"
            return

        if not alive and drilling:
            self._s = "Drilling in progress..."
            return
        
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
        
        self._s = str(table)
        
from prettytable import PrettyTable
from termcolor import colored
