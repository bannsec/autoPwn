
"""
Silly wrapper to help set your environment variables correctly for the AFL on the given binary.
"""

import argparse
import fuzzer
import os
import tempfile

def parse_args():
    parser = argparse.ArgumentParser(description='Sets your environment variables appropriately for AFL against your given binary.')

    # Core Options
    parser.add_argument('file', metavar='file',type=str, help='The file you want to use AFL things on.')

    return parser.parse_args()

def main():
    args = parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        # Fuzzer will setup the base environment variables needed
        f = fuzzer.Fuzzer(args.file, tmpdir)

        # The relative dir to the AFL bins
        afl_path = os.path.abspath(os.environ['AFL_PATH'])
        afl_bin_dir = os.path.join(afl_path, "..", "..")
        os.environ['PATH'] = afl_path + ":" + afl_bin_dir + ":" + os.environ['PATH']

        # Give them a shell
        os.system("/bin/bash")

if __name__ == '__main__':
    main()
