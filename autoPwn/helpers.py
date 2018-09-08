
#
# Random helpers that I don't know where else to put...
#

from . import Config as GlobalConfig

def is_addr_starting_bb(addr):
    """Checks if the address given is the start of a known block.

    Returns: bool"""
    assert type(addr) == int, "Unexpected type for addr of {}".format(type(addr))

    cfg = GlobalConfig.get_proj_cfg()
    return any(b.addr == addr for b in cfg.nodes())

def find_node_addr(addr):
    """Work backwards from the given address to guess a starting address for the node.

    Returns int or None if couldn't find"""

    while not is_addr_starting_bb(addr) and addr >= GlobalConfig.proj.loader.main_object.min_addr:
        addr -= 1
    
    if addr < GlobalConfig.proj.loader.main_object.min_addr:
        return None

    return addr
