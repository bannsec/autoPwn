
import tracer
from .Config import global_config as GlobalConfig

class Tracer(object):
    """Simple Tracer wrapper for now."""

    def __init__(self, bin_input):
        """bin_input == concrete input to trace execution from."""
        self.input = bin_input

        self._tracer = tracer.QEMURunner(binary=GlobalConfig.target, input=self.input, argv=GlobalConfig.argv, record_stdout=True)

    @property
    def trace(self):
        """list: Trace of blocks that were hit."""
        return self._tracer.trace
        
    @property
    def stdout(self):
        """str: Stdout from execution."""
        return self._tracer.stdout
