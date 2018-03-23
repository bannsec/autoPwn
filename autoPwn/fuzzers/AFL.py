import logging
logger = logging.getLogger("autoPwn.fuzzers.AFL")

import os
import subprocess
import shlex
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

AFL_ROOT = "/home/angr/.virtualenvs/angr/bin/afl-unix/"

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
        self.kill()
        exit(0)

    @staticmethod
    def compile_file(source, ASAN, MSAN, UBSAN):
        full_path = os.path.abspath(source)
        base = os.path.basename(full_path)
        dir = os.path.dirname(full_path)
        env = copy(os.environ)
        env['AFL_HARDEN'] = '1' # TODO: Make this an option?

        out_name = "afl_" + '.'.join(base.split(".")[:-1])

        # Guess which to use
        if base.split(".")[-1].lower() in ["cpp", "cc", "C", "cxx", "c++"]:
            clang = os.path.join(AFL_ROOT, "afl-clang++")
        else:
            clang = os.path.join(AFL_ROOT, "afl-clang")

        # Assuming CLang for now.
        #compile_line = "{clang} -fsanitize=address -fsanitize=memory -fno-omit-frame-pointer -O1 -g {source} -o {out_name}".format(source=base, out_name=out_name, clang=clang)
        compile_line = [clang,'-fno-omit-frame-pointer','-O2','-g']

        # These are exclusive
        if ASAN:
            env['AFL_USE_ASAN'] = "1"
            #compile_line.append('-fsanitize=address')
        elif MSAN:
            env['AFL_USE_MSAN'] = "1"
            #compile_line.append('-fsanitize=memory')
            #compile_line.append('-fsanitize-memory-track-origins')
        
        # This apparently might cause issues with AFL
        #if UBSAN:
        #    compile_line.append('-fsanitize=undefined')

        compile_line.append('-o')
        compile_line.append(out_name)
        compile_line.append(base)

        subprocess.check_output(compile_line, cwd=dir, env=env)

        # Return the name of the new file
        return os.path.join(dir, out_name)

    @staticmethod
    def compile_make(command, ASAN, MSAN, UBSAN):
        env = copy(os.environ)
        env['AFL_HARDEN'] = '1' # TODO: Make this an option?
        env['CC'] = os.path.join(AFL_ROOT, "afl-clang")
        env['CXX'] = os.path.join(AFL_ROOT, "afl-clang++")
        env['CFLAGS'] = "-fno-omit-frame-pointer -O2 -g"
        env['CXXFLAGS'] = "-fno-omit-frame-pointer -O2 -g"

        # These are exclusive
        if ASAN:
            env['AFL_USE_ASAN'] = "1"
        elif MSAN:
            env['AFL_USE_MSAN'] = "1"

        subprocess.call(command, env=env, shell=True)

    ##############
    # Properties #
    ##############

    @property
    def fuzzer(self):
        """The fuzzer instance. Automatically created if it was set to None."""

        if self.__fuzzer is None:
            self.__fuzzer = fuzzer.Fuzzer(self.target, self.work_dir, afl_count=self.threads, qemu=self.qemu, target_opts=self.target_args, memory="99999T")
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
