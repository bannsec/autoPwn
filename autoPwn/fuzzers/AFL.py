import logging
logger = logging.getLogger("autoPwn.fuzzers.AFL")

import os
import subprocess
import shlex
from prettytable import PrettyTable
from glob import glob
import hashlib
import watchdog, watchdog.observers
import atexit
from time import sleep

from . import *
from ..Config import global_config as GlobalConfig

try:
    import tracer, angr, fuzzer, shellphish_afl
except:
    logger.error("Unable to find required angr/mechaphish libraries. Make sure mechaphish is installed.")
    exit(1)

# Just to be sure...
try:
    input = raw_input
except:
    pass

AFL_ROOT = shellphish_afl.afl_dir('unix')

class AFL(Fuzzer):

    def __init__(self, bininfo):
        
        self.fuzzer = None
        self.target = GlobalConfig.target
        self.target_args = GlobalConfig.arguments
        self.work_dir = GlobalConfig.work_dir
        self.threads = GlobalConfig.threads
        self.seeds = GlobalConfig.seeds

        # Use QEMU or not?
        self.qemu = not bininfo.afl
        self.dictionary = None

        if GlobalConfig.args.disable_odr_violations:
            os.environ['ASAN_OPTIONS'] = 'abort_on_error=1:symbolize=0:detect_odr_violation=0'

        self.realtime_collect_dir = os.path.join(self.work_dir, 'collect')

        self._setup_watchdog()

    #########
    # Calls #
    #########
    # Implement these in your class!

    def alive(self):
        """bool: Is the fuzzer alive and running?"""
        return self.fuzzer.alive

    def stats(self):
        """str: Return string representing stats of AFL fuzzing."""
        # afl_version

        table = PrettyTable([" ","bitmap","cycles","execs","pfavs","tfavs","crash","hang"])
        table.border = False # Border only takes up space!

        fuzzer_stats = self.fuzzer.stats
        
        # Each fuzzer instance is a row
        for fuzzerName in sorted(fuzzer_stats):
            fuzzerInstance = fuzzer_stats[fuzzerName]
            
            table.add_row([
                fuzzerName,
                fuzzerInstance['bitmap_cvg'],
                fuzzerInstance['cycles_done'],
                fuzzerInstance['execs_done'],
                fuzzerInstance['pending_favs'],
                fuzzerInstance['paths_favored'],
                fuzzerInstance['unique_crashes'],
                fuzzerInstance['unique_hangs'],
            ])
        
        return str(table)

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

    """
    def collect_crashes(self):
        " ""Combines all crashes into single directory." ""

        crashes_dir = os.path.abspath(os.path.join(self.fuzzer.out_dir, "..", "crashes"))

        for f in glob(os.path.join(self.fuzzer.out_dir, "*", "crashes", "*")):
            if os.path.basename(f) == "README.txt":
                pass
    """

    def _setup_watchdog(self):
        """Setup watcher for new crashes and paths."""

        self._watchdog_observer = watchdog.observers.Observer()
        self._watchdog_handler = WatchdogHandler(self, self._watchdog_observer)

        os.makedirs(self.fuzzer.out_dir, exist_ok=True)

        # If this is an initial run, hook into the base directory
        if glob(os.path.join(self.fuzzer.out_dir, "*", "crashes")) == []:
            self._watchdog_observer.schedule(self._watchdog_handler, os.path.abspath(self.fuzzer.out_dir), recursive=False)
        
        # Otherwise, hook the output folders right away
        else:

            # Limiting watchdog to specific folders to avoid thrashing
            for path in glob(os.path.join(self.fuzzer.out_dir, "*", "crashes")):
                self._watchdog_observer.schedule(self._watchdog_handler, path, recursive=False)

            for path in glob(os.path.join(self.fuzzer.out_dir, "*", "queue")):
                self._watchdog_observer.schedule(self._watchdog_handler, path, recursive=False)

        self._watchdog_observer.start()
        atexit.register(self._watchdog_observer.stop)


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
            self.__fuzzer = fuzzer.Fuzzer(self.target, self.work_dir, afl_count=self.threads, qemu=self.qemu, target_opts=self.target_args, memory="none", seeds=self.seeds)
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

    @property
    def realtime_collect_dir(self):
        return self.__realtime_collect_dir

    @realtime_collect_dir.setter
    def realtime_collect_dir(self, realtime_collect_dir):
        os.makedirs(os.path.join(realtime_collect_dir, "crashes"), exist_ok=True)
        os.makedirs(os.path.join(realtime_collect_dir, "queue"), exist_ok=True)

        self.__realtime_collect_dir = realtime_collect_dir

class WatchdogHandler:
    def __init__(self, afl, observer):
        # AFL parent class
        self.afl = afl
        self._handlers = []
        self._my_observer = observer

    def dispatch(self, event):

        if isinstance(event, watchdog.events.DirCreatedEvent):
            return self._dispatch_new_dir(event)

        if not isinstance(event, watchdog.events.FileModifiedEvent):
            return

        # handler.event.event_type == 'modified' and not handler.event.is_directory

        type_of = os.path.basename(os.path.dirname(event.src_path))
        logger.debug('New input discovered: ' + type_of + ': ' + repr(event))

        with open(event.src_path, 'rb') as f:
            data = f.read()

        fhash = hashlib.sha256(data).hexdigest()

        with open(os.path.join(self.afl.realtime_collect_dir, type_of, fhash), 'wb') as f:
            f.write(data)


    def _dispatch_new_dir(self, event):
        """Using this to catch the setup of new sync/output/crash directories."""

        logger.debug('New dir: ' + repr(event))
        dirname = os.path.basename(event.src_path)

        if dirname.startswith('fuzzer-'):

            watchdog_observer = watchdog.observers.Observer()
            watchdog_handler = WatchdogHandler(self.afl, watchdog_observer)

            watchdog_observer.schedule(watchdog_handler, os.path.join(event.src_path, 'crashes'), recursive=False)
            watchdog_observer.schedule(watchdog_handler, os.path.join(event.src_path, 'queue'), recursive=False)
            
            # Race condition with AFL creating the directory structure
            sleep(0.1)
            logger.debug('Starting monitor for dirs: ' + os.path.join(event.src_path, 'crashes') + ' ' + os.path.join(event.src_path, 'queue'))
            watchdog_observer.start()
            atexit.register(watchdog_observer.stop)

            # Keep it in a list so it doesn't get garbage collected
            self._handlers += [watchdog_handler, watchdog_observer]
