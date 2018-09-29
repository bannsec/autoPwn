
from ..Config import global_config as GlobalConfig

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
        fuzzer = GlobalConfig.queues['fuzzer']
        
        fuzzer.put({
            'command': 'stats',
            'replyto': self._me
        })
        
        self._s = GlobalConfig.queues[self._me].get()
        
from termcolor import colored
