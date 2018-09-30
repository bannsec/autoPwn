# Container to hold global config

import logging
logger = logging.getLogger("autoPwn.Config")

import os
import subprocess
import multiprocessing
import angr

HERE = os.path.dirname(os.path.realpath(__file__))
AUTOPWN_ARGV_SIZE = 64 # Default size for argv[i] buffer

class GlobalConfig(object):

    #
    # Methods
    #

    def setup_argv_fuzzing(self):
        """Update args to accont for argv fuzzing."""
        args = self._autoPwn_args
        
        # If no position holders, then return
        if "@@@" not in args.argument:
            return

        # Parse out which args (for instance, [1] if "@@@" is the first argument, [1,5] for the first and fifth, etc).
        args.fuzzed_argument = [i+1 for i, val in enumerate(args.argument) if val == "@@@"]

        # Figure out what arch we're dealing with
        target = args.binary[0]
        proj = angr.Project(target,load_options={'auto_load_libs': False})

        # Supported archs
        arch = proj.loader.main_object.arch.name
        if arch in ["AMD64", "X86"]:
            logger.warn("Fuzzing argv requires a little binary modification. Creating and fuzzing .patched.")
            logger.warn("Fuzzer->Driller handoff for argv fuzzing is likely broken. Recommend using '--disable-drill' option for now.") # TODO: Make driller handoff work...

            # Set environment vars
            os.environ['AUTOPWN_ARGV'] = ",".join(str(i) for i in args.fuzzed_argument)
            os.environ['AUTOPWN_ARGV_SIZE'] = ",".join([str(AUTOPWN_ARGV_SIZE)] * len(args.fuzzed_argument)) # TODO: Maybe this should be an optional variable?

            subprocess.check_output(['patch', target, os.path.join(HERE, "patches", "argv_{}.py".format(arch.lower()))], env=os.environ)

            # Overwrite the calling args
            args.binary[0] = target + ".patched"
            for i in args.fuzzed_argument:
                args.argument[i - 1] = "A"*AUTOPWN_ARGV_SIZE
                #args.argument[int(os.environ['AUTOPWN_ARGV']) - 1] = "A"*AUTOPWN_ARGV_SIZE

        else:
            logger.error("Currently do not support argv fuzzing for architecture '{}'".format(arch))
            exit(1)

    def populate_config_from_args(self, args):
        """Populates this config via command line args."""

        self._autoPwn_args = args # Save off command-line parsed args
        self.setup_argv_fuzzing()

        print("Setting up fuzz configuration")

        self.target = args.binary[0]
        self.threads = multiprocessing.cpu_count()
        self.work_dir = os.path.abspath("work")
        self.memory = "8G"
        self.arguments = args.argument


    def writeConfig(self, config):
        logger.warn("Not writing configs for the moment...")
        return
        with open("autoPwn.config","w") as f:
            f.write("[afl.dirs]\n")
            f.write("work = {0}\n".format(config["workDir"]))
            f.write("\n[target]\n")
            f.write("target = {0}\n".format(config["target"]))
            f.write("\n[afl.ctrl]\n")
            f.write("file = \n")
            f.write("timeout = 200+\n")
            f.write("mem_limit = {0}\n".format(config["memory"]))
            f.write("qemu = on\n")
            f.write("threads = {0}\n".format(config['threads']))
            #f.write("cpu_affinity = {0}".format(' '.join([str(x) for x in range(config['threads'])])) + "\n")
            f.write("\n[afl.behavior]\n")
            f.write("dirty = off\n")
            f.write("dumb = off\n")
            f.write("arguments = {0}".format(config["arguments"]))

    def readConfig(self,config_file):
        logger.warn("Not reading configs for the moment...")
        return
        config = configparser.ConfigParser()
        config.read(config_file)
        newConfig = {}
        newConfig['workDir'] = config['afl.dirs']['work']
        newConfig['target'] = config['target']['target']
        newConfig['memory'] = int(config['afl.ctrl']['mem_limit'])
        #newConfig['threads'] = len(config['afl.ctrl']['cpu_affinity'].split(" "))
        newConfig['threads'] = int(config['afl.ctrl']['threads'])
        
        return newConfig

    #
    # Properties
    #
    
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

    @property
    def threads(self):
        return self.__threads

    @threads.setter
    def threads(self, threads):
        assert type(threads) == int, "Unexpected type for threads of {}".format(type(threads))
        self.__threads = threads

    @property
    def target(self):
        """str: Binary to fuzz/drill."""
        return self.__target

    @target.setter
    def target(self, target):
        assert type(target) is str, "Unexpected type for target of {}".format(type(target))

        target = os.path.abspath(target)
        
        # Ensure the file exists
        if not os.path.isfile(target):
            print("That file doesn't appear to exist...")
            exit(1)

        self.__target = target

    @property
    def memory(self):
        """str: Max memory size -- i.e.: 8G"""
        return self.__memory

    @memory.setter
    def memory(self, memory):
        assert type(memory) is str, "Unexpected type for memory of {}".format(type(memory))
        self.__memory = memory

    @property
    def arguments(self):
        """list: argv array to run the binary with."""
        return self.__arguments

    @arguments.setter
    def arguments(self, arguments):
        assert type(arguments) is list, "Unexpected type for arguments of {}".format(type(arguments))
        self.__arguments = arguments

    @property
    def argv(self):
        """list: Full argv list. I.e.: ["./calc","arg1","arg2"]"""
        return [self.target] + self.arguments

    @property
    def cores(self):
        """int: Number of cores to use when fuzzing. Defaults to the total number of cores available."""
        return multiprocessing.cpu_count()

    @property
    def work_dir(self):
        """str: Path to working directory for this fuzz run."""
        return self.__work_dir

    @work_dir.setter
    def work_dir(self, work_dir):
        if not os.path.exists(work_dir):
            os.makedirs(work_dir)
        elif not os.path.isdir(work_dir):
            logger.error("Work dir '{}' exists but is not a directory?".format(work_dir))
            exit(1)

        self.__work_dir = work_dir

try:
    global_config
except:
    global_config = GlobalConfig()

