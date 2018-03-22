import argparse
from . import fuzzers
import os

def main():

    parser = argparse.ArgumentParser(description='Compile source to binaries for use in autoPwn.')
    parser.add_argument('--file', type=str, default=None,
                        help = "Single file to compile.")
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


def compile_file(file_name, fuzzer, ASAN, MSAN, UBSAN):

    # Make abs path to file
    file_path = os.path.abspath(file_name)

    # Call fuzzer
    out_name = fuzzers.fuzzers[fuzzer].compile_file(file_path, ASAN, MSAN, UBSAN)

    print("Output file is at: " + os.path.abspath(out_name))
    

if __name__ == '__main__':
    main()
