import logging
logger = logging.getLogger("autoPwn.fuzzers.AFL")

import os
from . import *

try:
    import tracer, angr, simuvex, fuzzer
except:
    logger.error("Unable to find required angr/mechaphish libraries. Make sure mechaphish is installed.")
    exit(1)

# Just to be sure...
try:
    input = raw_input
except:
    pass

class AFL(Fuzzer):

    def __init__(self, target, target_args, work_dir, threads, queues, bininfo):
        
        self.fuzzer = None

        self.target = target
        self.target_args = target_args
        self.work_dir = work_dir
        self.threads = threads
        self.queues = queues

        # Use QEMU or not?
        self.qemu = not bininfo.afl
        self.dictionary = None

    #########
    # Calls #
    #########
    # Implement these in your class!

    def alive(self):
        """bool: Is the fuzzer alive and running?"""
        return self.fuzzer.alive

    def stats(self):
        return self.fuzzer.stats

    def start(self):
        """Start the fuzzer."""
        self.fuzzer.start()

    def kill(self):
        """Kill the fuzzer."""
        if self.fuzzer.alive:
            self.fuzzer.kill()
            self.fuzzer = None # Do i need to kill it like this?

    def get_paths(self):
        return self.fuzzer.queue()

    def get_bitmap(self):
        """Return AFL map of paths for currently known paths."""
        return self.fuzzer.bitmap()

    def pollenate(self, paths):
        """pollenate the fuzzer with new seeds."""
        self.fuzzer.pollenate(paths)

    def set_dictionary(self, dictionary):
        """Sets the dictionary for this fuzzer to work with."""
        self.dictionary = dictionary

        # Need to restart if we are running
        if self.fuzzer.alive:
            self.fuzzer.kill()
            self.fuzzer = None
            self.fuzzer.start()

        # If we're not alive, just set the variable
        else:
            self.fuzzer.dictionary = dictionary

    def quit(self):
        exit(0)

    ##############
    # Properties #
    ##############

    @property
    def fuzzer(self):
        """The fuzzer instance. Automatically created if it was set to None."""

        if self.__fuzzer is None:
            self.__fuzzer = fuzzer.Fuzzer(self.target, self.work_dir, afl_count=self.threads, qemu=self.qemu, target_opts=self.target_args)
            self.__fuzzer.dictionary = self.dictionary

        return self.__fuzzer

    @fuzzer.setter
    def fuzzer(self, fuzzer):
        self.__fuzzer = fuzzer

    @property
    def status(self):
        """int: Return the status of the fuzzer."""
        raise Exception("Not implemented.")

    @property
    def qemu(self):
        """bool: To use QEMU mode for AFL fuzzing."""
        return self.__qemu

    @qemu.setter
    def qemu(self, qemu):
        assert type(qemu) is bool, "Invalid type for qemu of '{}'".format(type(qemu))
        self.__qemu = qemu

    @property
    def dictionary(self):
        """str: Full path to dictionary for AFL to use."""
        return self.__dictionary

    @dictionary.setter
    def dictionary(self, dictionary):
        # Santiy check. Don't try to set a path that doesn't exist
        if type(dictionary) is str and not os.path.exists(dictionary):
            logger.error("Dictionary doesn't exist! Not setting.")
            self.__dictionary = None

        else:
            self.__dictionary = dictionary
