import argparse
from . import fuzzers
import os

epilog = """
examples:

  Compile a specific .c file with AFL (default) and MSAN
    - autoPwnCompile --file test.c --MSAN

  Run configure script to build for utilizing AFL for the resultant binaries. Add ASAN as well.
    - autoPwnCompile --ASAN --make "./configure --without-threading"
    - autoPwnCompile --ASAN --make "make"
"""

def main():

    parser = argparse.ArgumentParser(description='Compile source to binaries for use in autoPwn.', epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    what = parser.add_mutually_exclusive_group()
    what.add_argument('--file', type=str, default=None,
                        help = "Single file to compile.")
    what.add_argument('--make', type=str, default=None,
                        help = "Run the given command with appropriate 'make' environment variables.")
    SANS = parser.add_mutually_exclusive_group()
    SANS.add_argument('--ASAN', action='store_true', default=False,
                        help = "Enable ASAN (default off)")
    SANS.add_argument('--MSAN', action='store_true', default=False,
                        help = "Enable MSAN (default off)")
    parser.add_argument('--UBSAN', action='store_true', default=False,
                        help = "Enable UBSAN (default off)")
    parser.add_argument('--fuzzer', default='AFL', type=str,
                        help='(optional) What fuzzer to compile for. Options are: {}. Default is AFL.'.format(fuzzers.fuzzers.keys()))
    args = parser.parse_args()

    if args.file is not None:
        compile_file(file_name=args.file, fuzzer=args.fuzzer, ASAN=args.ASAN, MSAN=args.MSAN, UBSAN=args.UBSAN)

    elif args.make is not None:
        compile_make(command=args.make, fuzzer=args.fuzzer, ASAN=args.ASAN, MSAN=args.MSAN, UBSAN=args.UBSAN)

def compile_make(command, fuzzer, ASAN, MSAN, UBSAN):
    # Call fuzzer
    fuzzers.fuzzers[fuzzer].compile_make(command, ASAN, MSAN, UBSAN)

def compile_file(file_name, fuzzer, ASAN, MSAN, UBSAN):

    # Make abs path to file
    file_path = os.path.abspath(file_name)

    # Call fuzzer
    out_name = fuzzers.fuzzers[fuzzer].compile_file(file_path, ASAN, MSAN, UBSAN)

    print("Output file is at: " + os.path.abspath(out_name))
    

if __name__ == '__main__':
    main()
