## Source code
```c
#include <stdio.h>

int main(void) {
    
    FILE *fp;
    char buf[0x80] = {};
    size_t flag_len = 0;

    printf("Welcome To DreamHack Wargame!\n");

    fp = fopen("/flag", "r");
    fseek(fp, 0, SEEK_END);
    flag_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fread(buf, 1, flag_len, fp);
    fclose(fp);

    printf("FLAG : ");

    fwrite(buf, 1, flag_len, stdout);
}

```
In this challenge, the main function only do print the flag.
So we just connect to netcat server and it will print out the flag immediately
```
$$ nc host3.dreamhack.games 12848
Welcome To DreamHack Wargame!
FLAG : DH{5cc72596cba7104569abb37f71b8ccf3}
```
SO easy challenge right!