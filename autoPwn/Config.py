# Container to hold global config

import angr

class GlobalConfig(object):
    
    @property
    def proj(self):
        """angr.Project.Project"""
        return self.__proj

    @proj.setter
    def proj(self, proj):
        assert isinstance(proj, angr.project.Project), "Invalid type for project of {}".format(type(proj))
        self.__proj = proj

    @property
    def cfg(self):
        """CFG from angr.Project"""
        try:
            self.__cfg
        except:
            self.__cfg = self.proj.analyses.CFG()
        return self.__cfg

    @property
    def queues(self):
        """dict: Dictionary of queues to use for multiprocess communication."""
        return self.__queues

    @queues.setter
    def queues(self, queues):
        assert type(queues) is dict, "Unexpected type for queues of {}".format(type(queues))
        self.__queues = queues

try:
    global_config
except:
    global_config = GlobalConfig()

