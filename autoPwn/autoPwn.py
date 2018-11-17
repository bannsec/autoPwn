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
from .Config import global_config as GlobalConfig
from .ui.console import ConsoleUI
from . import modules
from . import fuzzers
from time import sleep
import sys
import angr, driller

CHECK_INTERVAL = 5
HERE = os.path.dirname(os.path.realpath(__file__))

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


def runAFL(cmd=None):
    cmd = "start" if cmd is None else cmd

    subprocess.check_output("afl-multicore -i - -c autoPwn.config {1} {0}".format(GlobalConfig.threads,cmd),shell=True)
    # It adds our python instance into the kill file too... Let's remove that :-)
    try:
        subprocess.check_output("grep -v {0} /tmp/afl_multicore.PGID.SESSION > /tmp/afl_multicore.PGID.SESSION2".format(os.getpgid(0)),shell=True)
    except:
        pass
    subprocess.check_output("mv /tmp/afl_multicore.PGID.SESSION2 /tmp/afl_multicore.PGID.SESSION",shell=True)


def collectExploits():
        exploits = os.path.abspath('exploits')
        subprocess.check_output("afl-collect -e gdb_script -j {0} -m -r -rr {1} {4} -- {2} {3}".format(GlobalConfig.threads,GlobalConfig.out_dir,GlobalConfig.target,GlobalConfig.cmdline,exploits),shell=True)
        exploitMin = os.path.abspath("exploit_min")
        
        try:
            os.mkdir(exploitMin)
        except:
            pass

        for exp in glob.glob(os.path.join(exploits,"S*")):
            #print("Checking",exp)
            base = os.path.basename(exp)
            o = subprocess.check_output("afl-tmin -i {0} -o {1} -Q -m {4} -- {2} {3}".format(exp,os.path.join(exploitMin,base),GlobalConfig.target,GlobalConfig.cmdline,GlobalConfig.memory),shell=True)
            #print(o.decode('ascii'))

        shutil.rmtree(exploits)

        print("Completed. Exploits in directory {0}".format(exploitMin))

def collectAllPaths():
        paths = os.path.abspath('paths')
        os.mkdir(paths)

        # TODO: Handle this better. Sometimes there will be dups
        try:
            subprocess.check_output("cp {0}/*/queue/* {1}".format(GlobalConfig.out_dir,paths),shell=True)
        except:
            pass

        pathsCMin = os.path.abspath("paths_cmin")
        
        try:
            os.mkdir(pathsCMin)
        except:
            pass

        subprocess.check_output("afl-cmin -i {0} -o {1} -Q -m {2} -- {3} {4}".format(paths,pathsCMin,GlobalConfig.memory,GlobalConfig.target,GlobalConfig.cmdline),shell=True)

        pathsMin = os.path.abspath("paths_min")
        
        try:
            os.mkdir(pathsMin)
        except:
            pass

        for exp in glob.glob(os.path.join(pathsCMin,"*")):
            #print("Checking",exp)
            base = os.path.basename(exp)
            o = subprocess.check_output("afl-tmin -i {0} -o {1} -Q -m {4} -- {2} {3}".format(exp,os.path.join(pathsMin,base),GlobalConfig.target,GlobalConfig.cmdline,GlobalConfig.memory),shell=True)
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

    fuzzstats = modules.fuzzerStats.FuzzerStats()

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

    dictionary = input("Directory or file to use as AFL dictionary: ")

    # Request the fuzzer to pollinate for us
    GlobalConfig.queues['fuzzer'].put({
        'command': 'set_dictionary',
        'replyto': None,
        'dictionary': dictionary
    })
    

def doPollinate():
    """Handle reading in new seeds and pollinating"""

    seeds = []

    pDir = input("Directory with seeds to pollinate: ")

    # Choosing to allow variables and expansions to make it easier to use
    pDir = os.path.expanduser(os.path.expandvars(pDir))

    # Read in the files
    for root, dirs, files in os.walk(pDir):
        for fName in files:
            with open(os.path.join(root,fName),"rb") as f:
                seeds.append(f.read())

    # Request the fuzzer to pollinate for us
    GlobalConfig.queues['fuzzer'].put({
        'command': 'pollenate',
        'replyto': None,
        'paths': seeds,
    })
    

def doStart():
    """Handle starting everything up."""
    
    # Start up the fuzzer   
    GlobalConfig.queues['fuzzer'].put({
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
    GlobalConfig.queues['fuzzer'].put({
        'command': 'quit',
        'replyto': None
    })

    GlobalConfig.queues['driller'].put({
        'command': 'quit',
        'replyto': None
    })
    
    exit(0)

##########################
# Driller Thread Section #
##########################

def _driller():
    binary = GlobalConfig.target
    procs = [] # TODO: Maybe remove dead procs??

    while True:

        item = GlobalConfig.queues['driller'].get()

        command = item['command']
        replyto = GlobalConfig.queues[item['replyto']] if item['replyto'] is not None else None

        if command == "alive":
            replyto.put(any(p.is_alive() for p in procs))

        elif command == "drill":

            # Spawn off subprocess for drilling
            p = multiprocessing.Process(target=_doDrill,kwargs={
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


def _doDrill(path,replyto,bitmap,binary):
    
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


def watcher():
    me = "watcher"
    
    while True:

        sleep(5)

        # If we haven't started yet, just pass
        GlobalConfig.queues['fuzzer'].put({
            'command': 'alive',
            'replyto': me
        })

        fuzzer_alive = GlobalConfig.queues[me].get()
        if not fuzzer_alive:
            continue
        
        # Grab the fuzzer stats
        GlobalConfig.queues['fuzzer'].put({
            'command': 'stats',
            'replyto': me
        })

        fuzzer_stats = GlobalConfig.queues[me].get()

        # If we have no more pending favs, we should move on.
        # TODO: Make fuzzer_stats_dict call to get this back as dict instead of str
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
            GlobalConfig.queues['fuzzer'].put({
                'command': 'kill',
                'replyto': None
            })

            # Grab the current paths
            GlobalConfig.queues['fuzzer'].put({
                'command': 'get_paths',
                'replyto': me
            })
    
            paths = GlobalConfig.queues[me].get()

            # Grab the current bitmap
            GlobalConfig.queues['fuzzer'].put({
                'command': 'get_bitmap',
                'replyto': me,
            })

            bitmap = GlobalConfig.queues[me].get()
            if bitmap == None:
                raise Exception("bitmap is None value. Something went wrong. Try removing the work directory and starting over again fresh")

            # Try to drill into each path
            for path in paths:
                
                # Submit the drill job
                GlobalConfig.queues['driller'].put({
                    'command': 'drill',
                    'replyto': me,
                    'path': path,
                    'bitmap': bitmap,
                })
                
                # Get the results
                new_paths = GlobalConfig.queues[me].get()

                # If we actually got results, time to reseed
                if len(new_paths) > 0:

                    # Request the pollination
                    GlobalConfig.queues['fuzzer'].put({
                        'command': 'pollenate',
                        'replyto': None,
                        'paths': list(new_paths),
                    })
                    
                    # Don't waste time drilling. See if AFL finds more now.
                    GlobalConfig.queues['fuzzer'].put({
                        'command': 'start',
                        'replyto': None,
                    })
                    
                    break

            else:
                # Don't waste time drilling. See if AFL finds more now.
                GlobalConfig.queues['fuzzer'].put({
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
    global args 

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

    asan_options = parser.add_argument_group('ASAN Options')
    asan_options.add_argument('--disable-odr-violations', default=False, action='store_true',
                        help='Sometimes the fuzzer won\'t start due to odr violations. You can disable that check with this flag.')

    #parser.add_argument('--no-auto-min', dest='no_auto_min', action='store_true',
    #                    help='Remove auto-prune functionality. It can still be done on-demand')
    #parser.set_defaults(no_auto_min=True)
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    args.config_file = None
    if args.config_file is None:
        GlobalConfig.populate_config_from_args(args)
        #writeConfig(config)

    else:
        config = readConfig(args.config_file)

    # Save it to the global config
    GlobalConfig.args = args

    # Setup some queues
    GlobalConfig.queues = {
        'fuzzer': multiprocessing.Queue(),
        'driller': multiprocessing.Queue(),
        'fuzzstats': multiprocessing.Queue(),
        'watcher': multiprocessing.Queue(),
        'main': multiprocessing.Queue(),
    }

    # Check binary is executable...
    if not os.access(GlobalConfig.target, os.X_OK):
        logger.error("Your binary is not executable! Be sure to chmod it, i.e.: chmod u+x {}".format(GlobalConfig.target))
        exit(1)

    if args.create_ram_mount:
        if os.path.exists(GlobalConfig.work_dir):
            logger.error("Mountpoint already exists. Not creating RAM disk!")
        else:
            os.makedirs(GlobalConfig.work_dir)
            subprocess.call(["sudo","mount","-t","tmpfs","-o","size={}m".format(args.create_ram_mount_size),"tmpfs",GlobalConfig.work_dir])

    # Load up the binary
    print("Loading up the binary")
    GlobalConfig.proj = angr.Project(GlobalConfig.target,load_options={'auto_load_libs': False})

    setupUI()

    # Start up fuzzer proc
    fuzzer = fuzzers.fuzzers[args.fuzzer](bininfo=bininfo)
    p = multiprocessing.Process(target=fuzzer.daemon)
    p.start()

    # Start up driller proc
    p = multiprocessing.Process(target=_driller)
    p.start()


    # Watch for the fuzzing to stall. This thread kicks off change into drilling
    if not args.disable_drill:
        p = multiprocessing.Process(target=watcher)
        p.daemon = True
        p.start()

    # Make sure everything is running before starting the UI
    GlobalConfig.queues['fuzzer'].put({
        'command': 'alive',
        'replyto': 'main'
    })
    GlobalConfig.queues['main'].get()

    GlobalConfig.queues['driller'].put({
        'command': 'alive',
        'replyto': 'main'
    })
    GlobalConfig.queues['main'].get()

    doMainMenu()


if __name__ == "__main__":
    main()

