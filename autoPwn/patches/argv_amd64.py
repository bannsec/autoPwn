import os

#
# Written by BannSec
# Be sure to set environment variable to specify which argv to fuzz and the size
# 
# Example: AUTOPWN_ARGV=1 AUTOPWN_ARGV_SIZE=16 patch <binary> argv_amd64.py
#

def patch(pt):
    argv_offset = 0x30

    # Which argv to fuzz. I.e.: 0,1,2,3
    argv = int(os.environ['AUTOPWN_ARGV'],0)

    # Size to fuzz
    size = int(os.environ['AUTOPWN_ARGV_SIZE'],0)

    base = pt.binary.next_alloc()
    addr = pt.inject(asm=r'''
    # Save regs
    push rax
    push rdi
    push rsi
    push rdx

    # Read in stuff
    mov rax, 0                   # SYS_read
    mov rdi, 0                   # fd
    mov rsi, [rsp + {offset:d}]  # buf
    mov rdx, {size:d}            # size
    syscall

    # Null terminate
    xor edx, edx                 # patchkit quirk. can't move immediate for now.
    mov [rsi + rax - 1], dl      # TODO: Assuming newline for now.. Probably shouldn't assume that.

    # Restore regs
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret
    '''.format(size=size, offset=(argv_offset + 8*argv)))
    pt.hook(pt.entry, addr)
