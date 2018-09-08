
import logging
logger = logging.getLogger("autoPwn.fuzzers")

from copy import copy
import os
import pkgutil
import importlib

from .. import Config as GlobalConfig

here = os.path.dirname(os.path.abspath(__file__))

# Base fuzzer class to extend
class Fuzzer(object):

    def __init__(self, target, target_args, work_dir, threads, bininfo):
        """Instantiate a new fuzzer.

        Args:
            target (str): location of binary to fuzz (full path)
            target_args (str): String arguments to pass to the binary.
            work_dir (str): location of directory to store work info (full path)
            threads (int): How many threads to use when fuzzing.
            bininfo: bininfo for more information about this binary.
        """
        raise Exception("Not implemented.")

    def daemon(self, *arg, **kargs):
        """Kick this class off as a daemon. It will be started as a process, so no need to split here.
        
        By default, the daemon handler will handle getting commands, and will
        call the method with the given command name. For instance, if the
        function called was "start", class.start() method would be called. If
        you want to return something to the caller, you can do so simply by
        passing it as the return param.
        
        See AFL module for examples of this."""
        
        logger.info("Starting daemon.")

        while True:

            # Get the next command
            item = GlobalConfig.queues['fuzzer'].get()
            command = item['command']
            replyto = GlobalConfig.queues[item['replyto']] if item['replyto'] is not None else None

            # Pull out the args to this call
            kwargs = copy(item)
            kwargs.pop('command')
            kwargs.pop('replyto')

            # Generically call it
            ret = getattr(self, command)(**kwargs)
            
            # If caller expects a reply, we better reply
            if replyto is not None:
                replyto.put(ret)

    #########
    # Calls #
    #########
    # Implement these in your class!

    def alive(self):
        """bool: Is the fuzzer alive and running?"""
        raise NotImplemented

    def stats(self):
        raise NotImplemented

    def start(self):
        """Start the fuzzer."""
        raise NotImplemented

    def kill(self):
        """Kill the fuzzer."""
        raise NotImplemented

    def get_paths(self):
        raise NotImplemented

    def get_bitmap(self):
        """Return AFL map of paths for currently known paths."""
        raise NotImplemented

    def pollenate(self, paths):
        """pollenate the fuzzer with new seeds."""
        raise NotImplemented

    def set_dictionary(self, dictionary):
        """Sets the dictionary for this fuzzer to work with."""
        raise NotImplemented

    def quit(self):
        exit(0)

    @staticmethod
    def compile_file(source, ASAN, MSAN, UBSAN):
        """Compile the source code as needed for this fuzzer. Return the name of the output file."""
        raise NotImplemented

    @staticmethod
    def compile_make(command, ASAN, MSAN, UBSAN):
        """Run the command with Make environment variables."""
        raise NotImplemented

    ##############
    # Properties #
    ##############

    @property
    def status(self):
        """int: Return the status of the fuzzer."""
        raise Exception("Not implemented.")

    @property
    def target(self):
        """str: location of binary to fuzz (full path)"""
        return self.__target

    @target.setter
    def target(self, target):
        assert type(target) is str, "Invalid type for target of '{}'".format(type(target))
        self.__target = target

    @property
    def work_dir(self):
        """str: location of directory to store work info (full path)"""
        return self.__work_dir

    @work_dir.setter
    def work_dir(self, work_dir):
        assert type(work_dir) is str, "Invalid type for work_dir of '{}'".format(type(work_dir))
        self.__work_dir = work_dir

    @property
    def threads(self):
        """int: Number of threads to use when fuzzing."""
        return self.__threads

    @threads.setter
    def threads(self, threads):
        assert type(threads) is int, "Invalid type for threads of '{}'".format(type(threads))
        self.__threads = threads
        
    @property
    def target_args(self):
        """str: String arguments to pass to the binary."""
        return self.__target_args

    @target_args.setter
    def target_args(self, target_args):
        self.__target_args = target_args

# Populate known fuzzers
if 'fuzzers' not in locals():
    fuzzers = {}

    # Loop through submodules
    for _, name, _ in pkgutil.iter_modules([here]):
        logger.info('Registering fuzzer: ' + name)
        fuzzers[name] = getattr(importlib.import_module('.'+name, 'autoPwn.fuzzers'),name)
