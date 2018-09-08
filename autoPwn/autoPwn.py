#!/usr/bin/env python

from . import Colorer
import logging
logger = logging.getLogger("autoPwn")

import os.path
import shutil
import subprocess
import multiprocessing
import threading
import signal
import re
import glob
import argparse
import configparser
from . import Config as GlobalConfig
from .ui.console import ConsoleUI
from . import modules
from . import fuzzers
from time import sleep
import sys
import angr, driller

CHECK_INTERVAL = 5
HERE = os.path.dirname(os.path.realpath(__file__))
AUTOPWN_ARGV_SIZE = 64 # Default size for argv[i] buffer

def checkFuzzerStatus(signum, frame):

    # Let fuzzstats prebuild
    fuzzstats.preDraw()
    
    # Refresh our display
    console.draw()

    # Reset our alarm
    signal.alarm(CHECK_INTERVAL)
    

def preChecks():
    # Checking for files that are needed
    if shutil.which("afl-fuzz") == None:
        print("Must have afl-fuzz installed: http://lcamtuf.coredump.cx/afl/")
        exit(1)

def setup_argv_fuzzing():
    global args
    
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


def getConfig():
    setup_argv_fuzzing()

    config = {}
    config['cycles_done'] = 0
    print("Setting up fuzz configuration")

    #target = input("Target Binary (full or relative path): ")
    target = args.binary[0]

    # Change it to abs path
    target = os.path.abspath(target)
    config["target"] = target
    
    # Ensure the file exists
    if not os.path.isfile(target):
        print("That file doesn't appear to exist...")
        exit(1)


    #cmdline = input("Command line args: ")
    #config["cmdline"] = cmdline

    defaultThreads = multiprocessing.cpu_count()
    #threads = input("Number of cores (default: {0}): ".format(defaultThreads))
    #threads = defaultThreads if threads == "" else int(threads)
    config["threads"] = defaultThreads
 

    #inDir = input("Test Case Dir (default: 'in/'): ")
    #inDir = "in" if inDir == "" else inDir
    workDir = os.path.abspath("work")
    config["workDir"] = workDir


    #outDir = input("Test Case Dir (default: 'out/'): ")
    #outDir = "out" if outDir == "" else outDir
    #outDir = os.path.abspath(outDir)
    #config["outDir"] = outDir


    #memory = input("Max memory (default: 200): ")
    #memory = int(memory) if memory is not "" else 200
    config["memory"] = "8G"
    
    config["arguments"] = args.argument

    return config


def writeConfig(config):
    with open("autoPwn.config","w") as f:
        f.write("[afl.dirs]\n")
        f.write("work = {0}\n".format(config["workDir"]))
        f.write("\n[target]\n")
        f.write("target = {0}\n".format(config["target"]))
        #f.write("cmdline = {0}\n".format(config["cmdline"]))
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

def readConfig(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    newConfig = {}
    newConfig['workDir'] = config['afl.dirs']['work']
    newConfig['target'] = config['target']['target']
    #newConfig['cmdline'] = config['target']['cmdline']
    newConfig['memory'] = int(config['afl.ctrl']['mem_limit'])
    #newConfig['threads'] = len(config['afl.ctrl']['cpu_affinity'].split(" "))
    newConfig['threads'] = int(config['afl.ctrl']['threads'])
    #newConfig['cycles_done'] = 0 # Intentionally going to be wrong here to initiate path clean
    
    return newConfig

def runAFL(cmd=None):
    cmd = "start" if cmd is None else cmd

    subprocess.check_output("afl-multicore -i - -c autoPwn.config {1} {0}".format(config['threads'],cmd),shell=True)
    # It adds our python instance into the kill file too... Let's remove that :-)
    try:
        subprocess.check_output("grep -v {0} /tmp/afl_multicore.PGID.SESSION > /tmp/afl_multicore.PGID.SESSION2".format(os.getpgid(0)),shell=True)
    except:
        pass
    subprocess.check_output("mv /tmp/afl_multicore.PGID.SESSION2 /tmp/afl_multicore.PGID.SESSION",shell=True)


def collectExploits():
        exploits = os.path.abspath('exploits')
        subprocess.check_output("afl-collect -e gdb_script -j {0} -m -r -rr {1} {4} -- {2} {3}".format(config['threads'],config['outDir'],config['target'],config['cmdline'],exploits),shell=True)
        exploitMin = os.path.abspath("exploit_min")
        
        try:
            os.mkdir(exploitMin)
        except:
            pass

        for exp in glob.glob(os.path.join(exploits,"S*")):
            #print("Checking",exp)
            base = os.path.basename(exp)
            o = subprocess.check_output("afl-tmin -i {0} -o {1} -Q -m {4} -- {2} {3}".format(exp,os.path.join(exploitMin,base),config['target'],config['cmdline'],config["memory"]),shell=True)
            #print(o.decode('ascii'))

        shutil.rmtree(exploits)

        print("Completed. Exploits in directory {0}".format(exploitMin))

def collectAllPaths():
        paths = os.path.abspath('paths')
        os.mkdir(paths)

        # TODO: Handle this better. Sometimes there will be dups
        try:
            subprocess.check_output("cp {0}/*/queue/* {1}".format(config['outDir'],paths),shell=True)
        except:
            pass

        pathsCMin = os.path.abspath("paths_cmin")
        
        try:
            os.mkdir(pathsCMin)
        except:
            pass

        subprocess.check_output("afl-cmin -i {0} -o {1} -Q -m {2} -- {3} {4}".format(paths,pathsCMin,config["memory"],config["target"],config["cmdline"]),shell=True)


        pathsMin = os.path.abspath("paths_min")
        
        try:
            os.mkdir(pathsMin)
        except:
            pass

        for exp in glob.glob(os.path.join(pathsCMin,"*")):
            #print("Checking",exp)
            base = os.path.basename(exp)
            o = subprocess.check_output("afl-tmin -i {0} -o {1} -Q -m {4} -- {2} {3}".format(exp,os.path.join(pathsMin,base),config['target'],config['cmdline'],config["memory"]),shell=True)
            #print(o.decode('ascii'))

        shutil.rmtree(paths)
        shutil.rmtree(pathsCMin)

        print("Completed. Paths in directory {0}".format(pathsMin))


def setupUI():
    global console, bininfo, fuzzstats
    console = ConsoleUI()


    #
    # Main Menu
    #  

    main_menu = modules.menu.Menu()
    main_menu.addItem("S","(S)tart searching")
    main_menu.addItem("O","(O)ptions")
    main_menu.addItem("Q","(Q)uit")

    fuzzstats = modules.fuzzerStats.FuzzerStats(queues)

    console.createView("MainMenu")
    console.setActiveView("MainMenu")
    console.registerModule(modules.banner.Banner(),height=20)
    bininfo = modules.binInfo.BinInfo()
    console.registerModule(bininfo,height=20)
    console.registerModule(fuzzstats,height=50)
    console.registerModule(main_menu,height=100)

    # 
    # Option Menu
    #

    options_menu = modules.menu.Menu()
    options_menu.addItem("P","(P)ollinate seeds from directory")
    options_menu.addItem("D","Force (D)rill")
    options_menu.addItem("X","Add Dictionary To Fuzzer")
    options_menu.addItem("Q","Back")
    
    console.createView("OptionsMenu")
    console.setActiveView("OptionsMenu")
    console.registerModule(modules.banner.Banner(),height=20)
    console.registerModule(options_menu,height=100)



def doMainMenu():
    
    while True:
        console.setActiveView("MainMenu")
        console.setPrompt("Select> ")

        console.draw()
        selection = console.input()

        if selection.upper() == "S":
            doStart()

        elif selection.upper() == "O":
            doOptionsMenu()

        elif selection.upper() == "Q":
            doExit()


def doOptionsMenu():
    
    while True:
        console.setActiveView("OptionsMenu")
        console.setPrompt("Select> ")

        console.draw()
        selection = console.input()

        if selection.upper() == "P":
            doPollinate()

        elif selection.upper() == "D":
            p = multiprocessing.Process(target=_orchestrateDrill,kwargs={'me':'main'})
            p.daemon = True
            p.start()

        elif selection.upper() == "X":
            doSetDictionary()

        elif selection.upper() == "Q":
            return


def doSetDictionary():
    """Handle setting the fuzzer dictionary"""

    dictionary = raw_input("Directory or file to use as AFL dictionary: ")

    # Request the fuzzer to pollinate for us
    queues['fuzzer'].put({
        'command': 'set_dictionary',
        'replyto': None,
        'dictionary': dictionary
    })
    

def doPollinate():
    """Handle reading in new seeds and pollinating"""

    seeds = []

    pDir = raw_input("Directory with seeds to pollinate: ")

    # Choosing to allow variables and expansions to make it easier to use
    pDir = os.path.expanduser(os.path.expandvars(pDir))

    # Read in the files
    for root, dirs, files in os.walk(pDir):
        for fName in files:
            with open(os.path.join(root,fName),"rb") as f:
                seeds.append(f.read())

    # Request the fuzzer to pollinate for us
    queues['fuzzer'].put({
        'command': 'pollenate',
        'replyto': None,
        'paths': seeds,
    })
    

def doStart():
    """Handle starting everything up."""
    
    # Start up the fuzzer   
    queues['fuzzer'].put({
        'command': 'start',
        'replyto': None
    })
    
    # Have fuzz predraw
    fuzzstats.preDraw()

    # Make sure to refresh our display
    signal.signal(signal.SIGALRM, checkFuzzerStatus)
    signal.alarm(CHECK_INTERVAL)
    

     
def doExit():
    # Tell our procs to exit
    queues['fuzzer'].put({
        'command': 'quit',
        'replyto': None
    })

    queues['driller'].put({
        'command': 'quit',
        'replyto': None
    })
    
    exit(0)

##########################
# Driller Thread Section #
##########################

def _driller(queues,binary):
    procs = [] # TODO: Maybe remove dead procs??

    while True:

        item = queues['driller'].get()

        command = item['command']
        replyto = queues[item['replyto']] if item['replyto'] is not None else None

        if command == "alive":
            replyto.put(any(p.is_alive() for p in procs))

        elif command == "drill":

            # Spawn off subprocess for drilling
            p = multiprocessing.Process(target=_doDrill,kwargs={
                'queues': queues,
                'path': item['path'],
                'replyto': replyto,
                'bitmap': item['bitmap'],
                'binary': binary,
            })
            p.daemon = True
            p.start()

            # Record our process
            procs.append(p)

        elif command == "quit":
            return


def _doDrill(queues,path,replyto,bitmap,binary):
    
    # Setup a new driller
    drill = driller.Driller(binary=binary,input_str=path,fuzz_bitmap=bitmap)

    # Drill drill drill
    results = drill.drill()

    # Grab the newly minted paths
    new_paths = set([result[1] for result in results])

    # Send them back
    replyto.put(new_paths)


##########################
# Watcher Thread Section #
##########################


def watcher(queues):
    me = "watcher"
    
    while True:

        sleep(5)

        # If we haven't started yet, just pass
        queues['fuzzer'].put({
            'command': 'alive',
            'replyto': me
        })

        fuzzer_alive = queues[me].get()
        if not fuzzer_alive:
            continue
        
        # Grab the fuzzer stats
        queues['fuzzer'].put({
            'command': 'stats',
            'replyto': me
        })

        fuzzer_stats = queues[me].get()

        # If we have no more pending favs, we should move on.
        pending_favs = sum(int(fuzzer_stats[x]['pending_favs']) for x in fuzzer_stats)

        # It's time to drill for some more
        if pending_favs == 0:
            _orchestrateDrill(me)


def _orchestrateDrill(me):
            """Orchestrating the drilling process
        
            Kill the fuzzer
            get bitmap
            try drilling for each
            reseed fuzzer with results
            restart fuzzer
            """
            
            # Kill the fuzzer, free up resources for drilling
            queues['fuzzer'].put({
                'command': 'kill',
                'replyto': None
            })

            # Grab the current paths
            queues['fuzzer'].put({
                'command': 'get_paths',
                'replyto': me
            })
    
            paths = queues[me].get()

            # Grab the current bitmap
            queues['fuzzer'].put({
                'command': 'get_bitmap',
                'replyto': me,
            })

            bitmap = queues[me].get()
            if bitmap == None:
                raise Exception("bitmap is None value. Something went wrong. Try removing the work directory and starting over again fresh")

            # Try to drill into each path
            for path in paths:
                
                # Submit the drill job
                queues['driller'].put({
                    'command': 'drill',
                    'replyto': me,
                    'path': path,
                    'bitmap': bitmap,
                })
                
                # Get the results
                new_paths = queues[me].get()

                # If we actually got results, time to reseed
                if len(new_paths) > 0:

                    # Request the pollination
                    queues['fuzzer'].put({
                        'command': 'pollenate',
                        'replyto': None,
                        'paths': list(new_paths),
                    })
                    
                    # Don't waste time drilling. See if AFL finds more now.
                    queues['fuzzer'].put({
                        'command': 'start',
                        'replyto': None,
                    })
                    
                    break

            else:
                # Don't waste time drilling. See if AFL finds more now.
                queues['fuzzer'].put({
                    'command': 'start',
                    'replyto': None,
                })

                print("WARNING: We were not able to drill more paths! You may be stuck. Perhaps try adding more seeds manually?")
                sleep(60*15) # Give AFL another 15 minutes of trying before we cut in again



################
# Main Section #
################

epilog = """
examples:

  Fuzz the translate command (tr) ARGV[1] and ARGV[2] positional arguments.
    - autoPwn ./ls @@@ @@@

  Fuzz the second argv command for translate.
    - autoPwn ./tr [:lower:] @@@
"""

def main():
    global queues, args, config

    parser = argparse.ArgumentParser(description='Automate some basic fuzzing management', epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('binary', type=str, nargs=1,
                        help = "Binary to auto fuzz")
    parser.add_argument('argument', type=str, nargs='*',
                        help='(optional) command line flags to give to the binary. You can use "@@" for AFL file parameter fuzz. Also, autoPwn specifically supports "@@@" to fuzz argv parameters themselves.')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='(optional) Enable debugging output.')
    parser.add_argument('--disable-drill', action='store_true', default=False,
                        help='Disable transitioning to drilling. This will keep autoPwn only in fuzzing mode.')
    parser.add_argument('--create-ram-mount', action='store_true', default=False,
                        help='Create a new ram mount for your work directory. Default: False')
    parser.add_argument('--create-ram-mount-size', type=int, metavar='size', default=512,
                        help='Specify size in MB for the RAM mount. Default: 512')
    parser.add_argument('--fuzzer', default='AFL', type=str,
                        help='(optional) What fuzzer to start with. Options are: {}. Default is AFL.'.format(fuzzers.fuzzers.keys()))
    #parser.add_argument('--no-auto-min', dest='no_auto_min', action='store_true',
    #                    help='Remove auto-prune functionality. It can still be done on-demand')
    #parser.set_defaults(no_auto_min=True)
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    args.config_file = None
    if args.config_file is None:
        config = getConfig()
        writeConfig(config)

    else:
        config = readConfig(args.config_file)

    # Setup some queues
    queues = {
        'fuzzer': multiprocessing.Queue(),
        'driller': multiprocessing.Queue(),
        'fuzzstats': multiprocessing.Queue(),
        'watcher': multiprocessing.Queue(),
        'main': multiprocessing.Queue(),
    }

    # Check binary is executable...
    if not os.access(config['target'], os.X_OK):
        logger.error("Your binary is not executable! Be sure to chmod it, i.e.: chmod u+x {}".format(config['target']))
        exit(1)

    if args.create_ram_mount:
        if os.path.exists(config['workDir']):
            logger.error("Mountpoint already exists. Not creating RAM disk!")
        else:
            os.makedirs(config['workDir'])
            subprocess.call(["sudo","mount","-t","tmpfs","-o","size={}m".format(args.create_ram_mount_size),"tmpfs",config['workDir']])

    # Load up the binary
    print("Loading up the binary")
    GlobalConfig.proj = angr.Project(config['target'],load_options={'auto_load_libs': False})

    setupUI()

    # Start up fuzzer proc
    fuzzer = fuzzers.fuzzers[args.fuzzer](target=config['target'], target_args=config['arguments'], work_dir=config['workDir'],threads=config['threads'],queues=queues,bininfo=bininfo)
    p = multiprocessing.Process(target=fuzzer.daemon)
    p.start()

    # Start up driller proc
    p = multiprocessing.Process(target=_driller,kwargs={'queues':queues,'binary':config['target']})
    p.start()


    # Watch for the fuzzing to stall. This thread kicks off change into drilling
    if not args.disable_drill:
        p = multiprocessing.Process(target=watcher,args=(queues,))
        p.daemon = True
        p.start()

    # Make sure everything is running before starting the UI
    queues['fuzzer'].put({
        'command': 'alive',
        'replyto': 'main'
    })
    queues['main'].get()

    queues['driller'].put({
        'command': 'alive',
        'replyto': 'main'
    })
    queues['main'].get()

    doMainMenu()


if __name__ == "__main__":
    main()

