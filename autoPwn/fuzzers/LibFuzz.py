
import logging
logger = logging.getLogger("autoPwn.fuzzers.LibFuzz")

import os
import subprocess
import signal
import shlex
from copy import copy
import magic
from . import *
from ..Config import global_config as GlobalConfig
from ..helpers import read_all_lines, recursive_kill

# Just to be sure...
try:
    input = raw_input
except:
    pass

class LibFuzz(Fuzzer):

    def __init__(self, bininfo):
        self._alive = False
        self.fuzzer = None
        self._stats = ""

        # Create dir if need be
        if not os.path.exists(self.seeds_dir):
            os.makedirs(self.seeds_dir)


    #########
    # Calls #
    #########
    # Implement these in your class!

    @staticmethod
    def _build_compile_env(source, ASAN, MSAN, UBSAN):
        """Override the current env with new CC and CXX vars for use in direct compiling and make and such. Returns the env dictionary."""

        env = copy(os.environ)
        full_path = os.path.abspath(source)

        # This warning only relevant when linking with the fuzzer
        if not GlobalConfig.args.no_fuzzer and not GlobalConfig.args.fuzzer_no_link:

            if os.path.isfile(source):
                # C? C++?
                file_magic = magic.from_file(full_path)
                if "C++ source" in file_magic:
                    func = """extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { <test here>; return 0 }"""
                else:
                    func = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { <test here>; return 0 }"""

            else:
                func = """extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { <test here>; return 0 }"""

            logger.warn("""Remember! You need to add the LibFuzz test function: 

                #include <stdint.h>
                {func}

            Also, you need to __NOT__ have a "main" defined.""".format(func=func))

        execute = ['-g','-O1','-fno-omit-frame-pointer']
        fuzz_options = []

        if not GlobalConfig.args.no_fuzzer and not GlobalConfig.args.fuzzer_no_link:
            fuzz_options.append("fuzzer")

        elif GlobalConfig.args.fuzzer_no_link:
            fuzz_options.append("fuzzer-no-link")

        if ASAN:
            fuzz_options.append("address")
        
        if MSAN:
            logger.warn("MSAN is experimental.")
            fuzz_options.append("memory")

            # TODO: Maybe remove this? This is experimental as well. Requires "MSAN_OPTIONS=poison_in_dtor=1" at runtime to enable.
            execute.append("-fsanitize-memory-use-after-dtor")

            # TODO: Also experimental. Maybe make option flag for this.
            execute.append("-fsanitize-memory-track-origins")

        if UBSAN:
            fuzz_options.append("signed-integer-overflow")

        # This requires "-use_value_profile=1" at runtime. Also, it will slow down fuzzing and increase seed size. Not sure if this changes anything without the activation at runtime though.
        execute.append("-fsanitize-coverage=trace-cmp")

        execute.append("-fsanitize=" + ",".join(fuzz_options))

        # Overriding CC params
        env['CC'] = " ".join(['clang'] + execute)
        env['CXX'] = " ".join(['clang++'] + execute)

        #env['CFLAGS'] = "-fno-omit-frame-pointer -O2 -g"
        #env['CXXFLAGS'] = "-fno-omit-frame-pointer -O2 -g"

        return env

    
    @staticmethod
    def compile_file(source, ASAN, MSAN, UBSAN):
        full_path = os.path.abspath(source)
        base = os.path.basename(full_path)
        dir = os.path.dirname(full_path)
        out_name = base + "_compiled"

        env = LibFuzz._build_compile_env(source, ASAN, MSAN, UBSAN)

        # C? C++?
        file_magic = magic.from_file(full_path)
        if "C++ source" in file_magic:
            command = shlex.split(env['CXX']) + ["-o", out_name, full_path]
        else:
            if "C source" not in file_magic:
                logger.warn("Couldn't determine source file language. Assuming C.")

            command = shlex.split(env['CC']) + ["-o", out_name, full_path]

        # Run it
        subprocess.check_output(command, cwd=dir, env=env)

        # Return the name of the new file
        return os.path.join(dir, out_name)

    @staticmethod
    def compile_make(command, ASAN, MSAN, UBSAN):
        env = LibFuzz._build_compile_env(".", ASAN, MSAN, UBSAN)

        subprocess.call(command, env=env, shell=True)


    def alive(self):
        """bool: Is the fuzzer alive and running?"""
        if self.fuzzer is None:
            return False

        # s.poll()  -- Returns None if process is alive, otherwise returns exit code
        alive = self.fuzzer.poll() is None

        # Save off any last error messages
        if not alive:
            self._append_to_log(self.fuzzer.stderr.read())
            self.fuzzer = None

        return alive

    def stats(self):
        new_stats = "\n".join(read_all_lines(self.fuzzer.stderr))
        self._stats += new_stats
        self._append_to_log(new_stats)
        return self._stats

    def start(self):
        """Start the fuzzer."""
        self.fuzzer = subprocess.Popen(self._run_args, env=self._run_env, bufsize=10240, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=GlobalConfig.work_dir)

    def kill(self):
        """Kill the fuzzer."""
        if self.alive:
            recursive_kill(self.fuzzer.pid)
            self.fuzzer = None # Do i need to kill it like this?

    """
    def get_paths(self):
        return self.fuzzer.queue()

    def get_bitmap(self):
        " ""Return AFL map of paths for currently known paths." ""
        return self.fuzzer.bitmap()

    def pollenate(self, paths):
        " ""pollenate the fuzzer with new seeds." ""
        self.fuzzer.pollenate(paths)

    def set_dictionary(self, dictionary):
        " ""Sets the dictionary for this fuzzer to work with." ""
        self.dictionary = dictionary

        # Need to restart if we are running
        if self.fuzzer.alive:
            self.fuzzer.kill()
            self.fuzzer = None
            self.fuzzer.start()

        # If we're not alive, just set the variable
        else:
            self.fuzzer.dictionary = dictionary
    """

    def quit(self):
        self.kill()
        exit(0)

    def _append_to_log(self, s):
        with open(self.logfile, "a") as f:
            f.write(s)

    ##############
    # Properties #
    ##############

    @property
    def logfile(self):
        """str: Path to log output of run."""
        return os.path.join(GlobalConfig.work_dir, "libfuzz.log")

    @property
    def _run_env(self):
        """dict: Environment dictionary to run with."""
        env = copy(os.environ)

        if GlobalConfig.args.disable_odr_violations:
            env['ASAN_OPTIONS'] = 'detect_odr_violation=0'

        return env

    @property
    def seeds_dir(self):
        """str: Path to directory that will house the seeds."""
        return os.path.join(GlobalConfig.work_dir, "seeds")

    @property
    def _run_args(self):
        """dict: Run arguments to be passed to subprocess.Popen."""
        # -jobs=8 -workers=8 -reduce_inputs=1 -use_counters=1 -print_final_stats=1 -close_fd_mask=3 -detect_leaks=1 -max_len 4096 rax2_inputs/
        return [GlobalConfig.target, "-print_pcs=1", "-seed=1", "-use_value_profile=1", "-reload=1", "-jobs=8","-workers=8","-reduce_inputs=1","-use_counters=1","-print_final_stats=1","-close_fd_mask=3","-detect_leaks=1","-max_len=4096", self.seeds_dir]

    @property
    def fuzzer(self):
        """Subprocess.Popen: Current handle to the running fuzzer subprocess."""
        return self.__fuzzer

    @fuzzer.setter
    def fuzzer(self, fuzzer):
        assert isinstance(fuzzer, (subprocess.Popen, type(None)))
        self.__fuzzer = fuzzer

    @property
    def status(self):
        """int: Return the status of the fuzzer."""
        raise Exception("Not implemented.")

    @property
    def dictionary(self):
        """str: Full path to dictionary for AFL to use."""
        logger.warn("Dictionary not implemented yet.")
        return self.__dictionary

    @dictionary.setter
    def dictionary(self, dictionary):
        # Santiy check. Don't try to set a path that doesn't exist
        if type(dictionary) is str and not os.path.exists(dictionary):
            logger.error("Dictionary doesn't exist! Not setting.")
            self.__dictionary = None

        else:
            self.__dictionary = dictionary
