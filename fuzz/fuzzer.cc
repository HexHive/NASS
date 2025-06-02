
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fuzzer.h"
#include "binderlib.h"
#include "fuzzparcel.h"
#include "FuzzedDataProvider.h"
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

using namespace android;

//__attribute__((section(
//    "__libfuzzer_extra_counters"))) unsigned char libfuzzer_coverage[FRIDA_MAP_SIZE];

BinderFuzzer bdfuzzer;

int __checkDeath(status_t status, pid_t pid){
    if(status == 0xffffffe0){return 1;}
    int s = kill(pid, 0);
    if(s==-1){return 1;
    } else {return 0;}
}

namespace fuzzer {
    uint8_t *ExtraCountersBegin(){LOGD("ExtraCountersBegin: %p\n", bdfuzzer.__frida_area_ptr); return bdfuzzer.__frida_area_ptr;}
    uint8_t *ExtraCountersEnd(){LOGD("ExtraCountersEnd(): %p\n", bdfuzzer.__frida_area_ptr+FRIDA_MAP_SIZE); return bdfuzzer.__frida_area_ptr+FRIDA_MAP_SIZE;}
}

#ifndef REPLAYONLY

static void __reset_frida_coverage(void) {
    memset(bdfuzzer.__frida_area_ptr, 0, FRIDA_MAP_SIZE); 
    msync(bdfuzzer.__frida_area_ptr, FRIDA_MAP_SIZE, MS_SYNC);
}

extern "C" void __sanitizer_set_crash_callback(void (*crashCallBack)(void)){
    printf("__sanitizer_set_crash_callback setting callback\n");
    bdfuzzer.crashCallBack = crashCallBack;
}

extern "C" void LLVMFuzzerPassDefaultMutators(void* LLVMDefaultMutators, void* LLVMMutationDispatcher, void* CurrentMutatorSequence){
    printf("LLVMFuzzerPassDefaultMutators called, dispatcher: %p\n", LLVMMutationDispatcher);
    SetDefaultMutators(LLVMDefaultMutators, LLVMMutationDispatcher, CurrentMutatorSequence);
}

extern "C" void LLVMFuzzerPassStats(size_t* TotalNumberOfRuns, size_t* NumberOfNewUnitsAdded, size_t* LastCorpusUpdateRun){
    printf("LLVMFuzzerPassStats called: %p, %p, %p\n", TotalNumberOfRuns, NumberOfNewUnitsAdded, LastCorpusUpdateRun);
    setStats(TotalNumberOfRuns, NumberOfNewUnitsAdded, LastCorpusUpdateRun);
}
#endif

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    printf("LLVMFuzzerInitialize setting up fuzzer\n");
    char* service_name = getenv("SERVICE_NAME"); 
    char* interface_name = getenv("INTERFACE_NAME");;
    char* parcel_read_used_path = getenv("DESER_PATH");;
    char* mutator_choice=NULL;

    if(service_name==NULL || interface_name==NULL || parcel_read_used_path==NULL){
        printf("the following env variables need to be set:\n");
        printf("SERVICE_NAME: name of the target service\n");
        printf("INTERFACE_NAME: the interface name of the target service\n");
        printf("DESER_PATH: path to file with deserialization functions\n");
        #ifndef REPLAYONLY
        printf("optional:\n");
        printf("WAIT_PID: used to synchronize with orchestrator\n");
        printf("DEBUG: enable debug logging\n");
        printf("DUMPALL: dump all output\n");
        printf("MUTATOR_CHOICE: CODE: only mutate command code, PARCEL: mutate parcel structure, DEFAULT: choose all mutators with equal probability, DATA: mutate structure of parcel only with low probability\n");
        printf("NOSHM: don't use actual shared memory, just use an internal memory region\n");
        printf("DUMP_REPLAY: when replaying a crash replay sorted list of files in this directory\n");
        #endif
        exit(-1);
    }

    if(getenv("DEBUG")){
        DEBUG = 1;
    }

    if(getenv("DUMPALL")){
        DUMP = 1;
        struct stat st = {0};
        if (stat("./dmp", &st) == -1) {
            mkdir("./dmp", 0777);
        } else {
            rmdir("./dmp");
            mkdir("./dmp", 0777); 
        }
    }

    if(getenv("FAKESHM")){
    	FAKESHM=1;
    }

    bdfuzzer.service_name = (char*)malloc(strlen(service_name)+10);
    strcpy(bdfuzzer.service_name, service_name);
    bdfuzzer.interface_name = (char*)malloc(strlen(interface_name)+10);
    strcpy(bdfuzzer.interface_name, interface_name);
    
#ifndef REPLAYONLY
    int wait_for_pid = 0;
    if(getenv("WAIT_PID")){
        LOGD("WAIT_PID enabled\n");
        wait_for_pid = 1;
    }
    char default_mutator[] = "DEFAULT";
    mutator_choice = getenv("MUTATOR_CHOICE");
    if(mutator_choice){
        if(strcmp(mutator_choice, "DEFAULT") == 0){
            printf("MUTATOR_CHOICE set to default, all mutators are chosen with equal probability\n");
        } else if(strcmp(mutator_choice, "DATA") == 0){
            printf("MUTATOR_CHOICE set to DATA, focusing on mutating parcel content\n");
        } else if(strcmp(mutator_choice, "PARCEL") == 0){
            printf("MUTATOR_CHOICE set to PARCEL, focusing on mutating parcel structure\n");
        } else if(strcmp(mutator_choice, "CODE") == 0){
            printf("MUTATOR_CHOICE set to CODE, focusing on mutating parcel code\n");
        } else if(strcmp(mutator_choice, "NODESER") == 0){
            printf("MUTATOR_CHOICE set to NODESER, unknown deserializing\n");
        } else{
            printf("MUTATOR_CHOICE unknown option: %s, resetting to default\n", mutator_choice);
            mutator_choice = default_mutator;
        }
    } else {
        printf("MUTATOR_CHOICE not set, resorting to DEFAULT, all mutators with equal probability\n");
        mutator_choice = default_mutator;
    }
#endif 

    // Initialize the mutator
    InitMutator(parcel_read_used_path, mutator_choice);

#ifndef REPLAYONLY
    // open pid dump file and dump the pid of the fuzzer
    FILE* pid_file = fopen(pid_path, "w+");
    if (pid_file == NULL) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    fprintf(pid_file, "%d", getpid());
    fclose(pid_file);

    // wait for pid ack
    if(wait_for_pid){
        LOGD("[..] waiting for pid_read");
        while(1){
        if(access(pid_ack_path, F_OK) == 0){
            break;
        }
        usleep(500000);
        }
    }

    unsigned char* frida_shared_mem;
    if(getenv("NOSHM")){
        printf("NOSHM specified, using fake frida shared memory region\n");
        frida_shared_mem = (unsigned char*)mmap(NULL, FRIDA_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE |MAP_ANONYMOUS, -1, 0);
    } else {
        // open the shared memory to the frida instrumentation
        int fd = open(shared_mem_path, O_RDWR, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            perror("open");
            exit(EXIT_FAILURE);
        }
        // Map the file into memory
        frida_shared_mem = (unsigned char*)mmap(NULL, FRIDA_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }
    if (frida_shared_mem == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    bdfuzzer.__frida_area_ptr = frida_shared_mem;
    LOGD("__frida_area_ptr: %p\n", bdfuzzer.__frida_area_ptr);
#else
    unsigned char* frida_shared_mem = (unsigned char*)mmap(NULL, FRIDA_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE |MAP_ANONYMOUS, -1, 0);
    bdfuzzer.__frida_area_ptr = frida_shared_mem; 
#endif
    LOGD("obtaining handle to Binder service\n");
    bdfuzzer.service =  new Service(bdfuzzer.service_name, bdfuzzer.interface_name);
    status_t status = bdfuzzer.service->getHandle();
    if(status != 0){
        fprintf(stderr, "failed to request service handle!\n");
        exit(-1);
    }
    pid_t pid = bdfuzzer.service->getPid();
    LOGD("service handle openend pid: %d\n", pid);
    bdfuzzer.service_pid = pid;

    #ifndef REPLAYONLY
    // obtaining the service handle generates coverage
    __reset_frida_coverage();
    #endif 

    return 0;
}

#ifndef REPLAYONLY
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
    if (getenv("DISABLE_CUSTOM_MUTATOR"))
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    else
        return ParcelMutator(Data, Size, MaxSize, Seed);
}
#endif

extern "C" int LLVMFuzzerTestOneInput(unsigned char *Data, size_t Size) {
    clock_t start;
    start = clock();
    LOGD("LLVMFuzzerTestOneInput %zu, %ld\n", Size, start);
    Parcel testcase, reply;
    uint32_t code;
#ifndef ANDROID9
    testcase.markForBinder(bdfuzzer.service->handle); 
#endif
    testcase.writeInterfaceToken(bdfuzzer.service->iname); 
    start = clock();
    code = create_parcel(&testcase, Data, Size);
    if(code == -1){
        return -1;
    }
    LOGD("serializing finished %f\n", ((double) (clock() - start)));
    start = clock();
    LOGD("sending request for command code %d\n", code);
    status_t status = bdfuzzer.service->transact(code, &testcase, &reply);
    LOGD("binder request sent: %d, %f\n", status, ((double) (clock() - start))); 
    start = clock();
    if(__checkDeath(status, bdfuzzer.service_pid)){
        printf("SERVICE CRASHED!\n");
        #ifndef REPLAYONLY
        bdfuzzer.crashCallBack();
        #else
        exit(0);
        #endif
    } 
    if(DUMP){
        iteration += 1;
        char fp[0x200];
        sprintf(fp, "./dmp/%lu", iteration);
        FILE* dmp = fopen(fp, "w+");
        fwrite(Data, 1, Size, dmp);
        fclose(dmp);
    }
    LOGD("checked for service death: %f\n", ((double) (clock() - start)));  
#ifndef ANDROID9
    std::vector<sp<IBinder>> binders = debugReadAllStrongBinders(&reply);
    for(int i=0; i < binders.size(); i++){
        String16 iDesc = binders[i]->getInterfaceDescriptor();
        char fp[0x100];
        sprintf(fp, "strongbinder-%s", String8(iDesc).c_str());
        FILE* dmp = fopen(fp, "w+");
        fwrite(Data, 1, Size, dmp);
        fclose(dmp); 
    }
#endif
    if(FAKESHM){
	*(char*)bdfuzzer.__frida_area_ptr = 1;
    }
    return 0;
}
