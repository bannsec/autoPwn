import os

#
# Written by BannSec
# Be sure to set environment variable to specify which argv to fuzz and the size
# 
# Example: AUTOPWN_ARGV=1,2 AUTOPWN_ARGV_SIZE=16,16 patch <binary> argv_amd64.py
#

asm_intro = r"""
# Save regs
push rax
push rdi
push rsi
push rdx
"""

asm_outro = r"""
pop rdx
pop rsi
pop rdi
pop rax
ret
"""

asm_read = r"""
# Read in stuff
mov rax, 0                   # SYS_read
mov rdi, 0                   # fd
mov rsi, [rsp + {offset:d}]  # buf
mov rdx, {size:d}            # size
syscall

# Null terminate
xor edx, edx                 # patchkit quirk. can't move immediate for now.
mov [rsi + rax - 1], dl      # TODO: Assuming newline for now.. Probably shouldn't assume that.
"""

def patch(pt):
    argv_offset = 0x30

    # Which argv to fuzz. I.e.: 0,1,2,3
    argv = [int(v,0) for v in os.environ['AUTOPWN_ARGV'].split(",")]

    # Size to fuzz
    size = [int(s,0) for s in os.environ['AUTOPWN_ARGV_SIZE'].split(",")]

    # Save off regs
    asm = asm_intro

    for a, s in zip(argv, size):
        # Read input from stdin
        asm += asm_read.format(size=s, offset=(argv_offset + 8*a))

    # Restore regs
    asm += asm_outro

    base = pt.binary.next_alloc()
    addr = pt.inject(asm=asm)
    pt.hook(pt.entry, addr)
