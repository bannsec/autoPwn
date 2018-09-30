
#
# Random helpers that I don't know where else to put...
#

from .Config import global_config as GlobalConfig
import select
import psutil

def is_addr_starting_bb(addr):
    """Checks if the address given is the start of a known block.

    Returns: bool"""
    assert type(addr) == int, "Unexpected type for addr of {}".format(type(addr))

    return any(b.addr == addr for b in GlobalConfig.cfg.nodes())

def find_node_addr(addr):
    """Work backwards from the given address to guess a starting address for the node.

    Returns int or None if couldn't find"""

    while not is_addr_starting_bb(addr) and addr >= GlobalConfig.proj.loader.main_object.min_addr:
        addr -= 1
    
    if addr < GlobalConfig.proj.loader.main_object.min_addr:
        return None

    return addr

def read_all_lines(pipe):
    """dict: Reads all available lines from the given PIPE. Does not block. NOTE: This assumes line output will always end up line terminated..."""
    assert isinstance(pipe, file), "read_all_lines argument needs to be a file type, got '{}' instead.".format(type(pipe))
    lines = []
    while select.select([pipe],[],[],0)[0] != []:
        lines.append(pipe.readline().strip())
    return lines

def recursive_kill(pid):
    """None: Recurisvely kill all children of pid, including pid."""
    proc = psutil.Process(pid=pid)
    
    for child in proc.children(recursive=True):
        child.kill()

    proc.kill()
