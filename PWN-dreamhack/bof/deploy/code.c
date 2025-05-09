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


