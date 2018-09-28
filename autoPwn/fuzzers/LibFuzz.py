
import logging
logger = logging.getLogger("autoPwn.fuzzers.LibFuzz")

import os
import subprocess
import shlex
import magic
from . import *
from ..Config import global_config as GlobalConfig

# Just to be sure...
try:
    input = raw_input
except:
    pass

class LibFuzz(Fuzzer):

    def __init__(self, bininfo):
        pass

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

            # C? C++?
            file_magic = magic.from_file(full_path)
            if "C++ source" in file_magic:
                func = """extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { <test here>; return 0 }"""
            else:
                func = """int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { <test here>; return 0 }"""

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


    """
    def alive(self):
        " ""bool: Is the fuzzer alive and running?"" "
        return self.fuzzer.alive

    def stats(self):
        return self.fuzzer.stats

    def start(self):
        " ""Start the fuzzer." ""
        self.fuzzer.start()

    def kill(self):
        " ""Kill the fuzzer." ""
        if self.fuzzer.alive:
            self.fuzzer.kill()
            self.fuzzer = None # Do i need to kill it like this?

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

    def quit(self):
        self.kill()
        exit(0)

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
        " ""The fuzzer instance. Automatically created if it was set to None." ""

        if self.__fuzzer is None:
            self.__fuzzer = fuzzer.Fuzzer(self.target, self.work_dir, afl_count=self.threads, qemu=self.qemu, target_opts=self.target_args, memory="none")
            self.__fuzzer.dictionary = self.dictionary

        return self.__fuzzer

    @fuzzer.setter
    def fuzzer(self, fuzzer):
        self.__fuzzer = fuzzer

    @property
    def status(self):
        " ""int: Return the status of the fuzzer." ""
        raise Exception("Not implemented.")

    @property
    def qemu(self):
        " ""bool: To use QEMU mode for AFL fuzzing." ""
        return self.__qemu

    @qemu.setter
    def qemu(self, qemu):
        assert type(qemu) is bool, "Invalid type for qemu of '{}'".format(type(qemu))
        self.__qemu = qemu

    @property
    def dictionary(self):
        " ""str: Full path to dictionary for AFL to use." ""
        return self.__dictionary

    @dictionary.setter
    def dictionary(self, dictionary):
        # Santiy check. Don't try to set a path that doesn't exist
        if type(dictionary) is str and not os.path.exists(dictionary):
            logger.error("Dictionary doesn't exist! Not setting.")
            self.__dictionary = None

        else:
            self.__dictionary = dictionary
    """
