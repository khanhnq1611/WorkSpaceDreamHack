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