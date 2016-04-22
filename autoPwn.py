#!/usr/bin/env python3

import os.path
import shutil
import multiprocessing


def preChecks():
    # Checking for files that are needed
    if shutil.which("afl-fuzz") == None:
        print("Must have afl-fuzz installed: http://lcamtuf.coredump.cx/afl/")
        exit(1)
    if shutil.which("afl-multicore") == None:
        print("Must have afl-utils installed: https://github.com/rc0r/afl-utils")
        exit(1)

def getConfig():
    config = {}
    print("Setting up fuzz configuration")

    target = input("Target Binary (full or relative path): ")
    # Change it to abs path
    target = os.path.abspath(target)
    config["target"] = target
    
    # Ensure the file exists
    if not os.path.isfile(target):
        print("That file doesn't appear to exist...")
        exit(1)


    cmdline = input("Command line args: ")
    config["cmdline"] = cmdline


    defaultThreads = multiprocessing.cpu_count()
    threads = input("Number of cores ({0}): ".format(defaultThreads))
    threads = defaultThreads if threads == "" else int(threads)
    config["threads"] = threads
 

    inDir = input("Test Case Dir ('in/'): ")
    inDir = "in" if inDir == "" else inDir
    inDir = os.path.abspath(inDir)
    config["inDir"] = inDir


    outDir = input("Test Case Dir ('out/'): ")
    outDir = "out" if outDir == "" else outDir
    outDir = os.path.abspath(outDir)
    config["outDir"] = outDir

    

    return config


def writeConfig(config):
    with open("autoPwn.config","w") as f:
        f.write("[afl.dirs]")
        f.write("input = {0}".format(config["inDir"]))
        f.write("output = {0}".format(config["outDir"]))
        f.write("[target]")
        f.write("target = {0}".format(config["target"]))
        f.write("cmdline = {0}".format(config["cmdline"]))
        f.write("[afl.ctrl]")
        f.write("file = ")
        f.write("timeout = 200+")
        f.write("mem_limit = 150")
        f.write("qemu = on")
        f.write("cpu_affinity = ".format(' '.join([str(x) for x in range(config['threads'])])))
        f.write("[afl.behavior]")
        f.write("dirty = off")
        f.write("dumb = off")
        f.write("[job]")
        f.write("session = SESSION")
        f.write("slave_only = off")
        f.write("interactive = off")
        

preChecks()

config = getConfig()

writeConfig(config)
