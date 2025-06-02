// pid_dump.c
#include <stdio.h>

void init() __attribute__((constructor));

 void init() {
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
     printf("PID: %d\n", getpid());
 }

