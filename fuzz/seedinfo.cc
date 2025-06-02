#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

#include "fuzzparcel.h"

#ifndef LOCALLIB
extern int DEBUG = 0;
#endif

int main(int argc, char** argv){
    if(argc < 2){
        printf("give me input path\n");
        return -1;
    }
    uint8_t buf[0x10000];
    size_t len;
    char* input_path = argv[1];

    FILE* file = fopen(input_path, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    len = ftell(file);
    rewind(file);
    if (fread(buf, 1, len, file) != len) {
        perror("Error reading file");
        fclose(file);
        return 1;
    }
    fclose(file);
    print_info(buf, len);
    return 0;
}