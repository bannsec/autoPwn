# Warning
Completely re-writing this right now. Focus will be on interactive Linux apps that only take input from stdin for starters. Attempting to use Shellphish's Driller and Fuzzer functionality.

autoPwn in it's current state will do this in limited form. Simply run `autoPwn ./binary` then select the Start option.

# Installing
Given all the dependency issues here, the easiest way to get autoPwn up and running is to use the Docker build.

```bash
$ sudo docker pull bannsec/autoPwn
$ sudo docker run -it -v $PWD:/mount
```

In the Docker build, everything should be ready to go. You can simply start up the tool with:

```bash
$ autoPwn ./file
```

The below is from the OLD version of autoPwn..

# Overview
autoPwn is a lofty name for a simple script. When working with fuzzing and afl-fuzz, I noticed that I would do the same tasks over and over. With this in mind, I wanted to create a script that would accomplish the following:


1. Automate and simplify the task of starting the fuzzer through smart prompts
2. Automate and simplify the task of restarting the fuzzer through a config file
3. Fully automate the process of afl queue minimizations
4. Fully automate the process of extracting and minimizing all possible exploitable paths
5. Fully automate the process of extracting and minimizing all possible paths in general.
6. Fully or partially automate the generation of initial path values.


So far, the script is able to the first 5. Part 6 is speculative and attempting development right now. It would leverage the angr symbolic execution engine to create possible initial paths. At that point, the script could theoretically fully automate *simple* fuzzing tasks.

# Example
Let's take a look at a recent TUCTF challenge called "WoO2". While it doesn't necessarily find the needed exploit, it does show how autoPwn can be used to simplify path discovery.

Here's a basic run through the program:

```text
$ ./e67eb287f23011a40ef5bd5c2ad2f48ca97834cf 
Welcome! I don't think we're in Kansas anymore.
We're about to head off on an adventure!
Select some animals you want to bring along.

Menu Options:
1: Bring a lion
2: Bring a tiger
3: Bring a bear
4: Delete Animal
5: Exit

Enter your choice:
1
Choose the type of lion you want:
1: Congo Lion
2: Barbary Lion
1
Enter name of lion:
Test
Menu Options:
1: Bring a lion
2: Bring a tiger
3: Bring a bear
4: Delete Animal
5: Exit

Enter your choice:
5
```

Let's create a simple input test case:

```text
$ cat in/1 
1
1
Test
5
```

Now we can easily start up the fuzzer:

```text
$ autoPwn 
Setting up fuzz configuration
Target Binary (full or relative path): e67eb287f23011a40ef5bd5c2ad2f48ca97834cf
Command line args: 
Number of cores (default: 8): 
Test Case Dir (default: 'in/'): 
Test Case Dir (default: 'out/'): 
Max memory (default: 200): 4096
Starting fuzz
autoPwn> s
status check tool for afl-fuzz by <lcamtuf@google.com>

Individual fuzzers
==================

>>> SESSION007 (0 days, 0 hrs) <<<

  cycle 1, lifetime speed 1 execs/sec, path 0/1 (0%)
  pending 1/1, coverage 0.15%, no crashes yet

>>> SESSION000 (0 days, 0 hrs) <<<

  cycle 1, lifetime speed 1 execs/sec, path 0/1 (0%)
  pending 1/1, coverage 0.15%, no crashes yet

>>> SESSION002 (0 days, 0 hrs) <<<

  cycle 1, lifetime speed 1 execs/sec, path 0/1 (0%)
  pending 1/1, coverage 0.15%, no crashes yet

>>> SESSION006 (0 days, 0 hrs) <<<

  cycle 1, lifetime speed 1 execs/sec, path 0/1 (0%)
  pending 1/1, coverage 0.15%, no crashes yet

>>> SESSION004 (0 days, 0 hrs) <<<

  cycle 1, lifetime speed 1 execs/sec, path 0/1 (0%)
  pending 1/1, coverage 0.15%, no crashes yet

>>> SESSION001 (0 days, 0 hrs) <<<

  cycle 1, lifetime speed 1 execs/sec, path 0/1 (0%)
  pending 1/1, coverage 0.15%, no crashes yet

>>> SESSION005 (0 days, 0 hrs) <<<

  cycle 1, lifetime speed 1 execs/sec, path 0/1 (0%)
  pending 1/1, coverage 0.15%, no crashes yet

>>> SESSION003 (0 days, 0 hrs) <<<

  cycle 1, lifetime speed 1 execs/sec, path 0/1 (0%)
  pending 1/1, coverage 0.15%, no crashes yet

Summary stats
=============

       Fuzzers alive : 8
      Total run time : 0 days, 0 hours
         Total execs : 0 million
    Cumulative speed : 8 execs/sec
       Pending paths : 8 faves, 8 total
  Pending per fuzzer : 1 faves, 1 total (on average)
       Crashes found : 0 locally unique


autoPwn> h
autoPwn
     s == fuzzer (s)tatus
     e == collect (e)xploits
     a == collect (a)ll paths
     m == (m)inimize corpus
     q == (q)uit
```

So what happened here was that the script created some default values (including determining the number of cores available). We changed one default value due to needing extra memory to run this in QEMU. autoPwn created a config file that it then gave to afl-utils (https://github.com/rc0r/afl-utils). In the config file, it also set up CPU affinities, so the fuzzing would be default optimal.

At this point, your computer is chucking away at fuzzing. However, one key aspect of fuzzing is minimizing the corpus. With this in mind, autoPwn is watching the afl-fuzz instance to monitor for when a series of the mutations are completed. When this happens, it will stop fuzzing (non-optimal, but fine for now), minimize the corpus, then re-start fuzzing. It does this without any human intervention so you can fire and forget.

At some point you might want to take a look at what paths afl has found. By executing the "a" command, autoPwn will copy all the known paths, minimize the corpus and then minimize the cases themselves and provide them in an output directory.
