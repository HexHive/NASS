#ifndef FUZZER_H
#define FUZZER_H

#include "binderlib.h"


int DEBUG = 0;
int DUMP = 0;
int FAKESHM = 0;
size_t iteration = 0;

#define LOGD(...) if(DEBUG){printf(__VA_ARGS__);}

// coverage between frida-instrumented target and fuzzer
const int FRIDA_MAP_SIZE = 0x8000;
char const *shared_mem_path = "/data/local/tmp/tmpfs/.shmem";

namespace fuzzer {
    uint8_t *ExtraCountersBegin();
    uint8_t *ExtraCountersEnd();
}

typedef struct BinderFuzzer {
    char *service_name;         
    char *interface_name;                
    unsigned char* __frida_area_ptr;
    Service* service;
    pid_t service_pid;
    void (*crashCallBack)(void);
} BinderFuzzer;

// important filepaths used for sync between frida-instrumented target, fuzzer and orchestrator
char const *pid_path = "./.pid";
char const *pid_ack_path = "./.pid_ack";
char const *do_interface_enum = "./.do_interface";
char const *do_interface_enum_ack = "./.do_interface_ack";
char const *do_interface_enum_done = "./.do_interface_done";

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

#endif
