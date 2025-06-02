#ifndef FUZZPARCEL_H
#define FUZZPARCEL_H

#include <sys/queue.h>
#include <unistd.h>

#ifndef LOCALLIB
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#else
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cassert>
#endif

#ifndef LOCALLIB
using namespace android;
#endif

#ifndef LOCALLIB
extern int DEBUG;
#else
extern int DEBUG=0;
#endif

#define LOGD(...) if(DEBUG){printf(__VA_ARGS__);}
#define LOGI(...) {printf(__VA_ARGS__);}


#define MAX_ENTRIES 100
#define NR_MUTATORS 5
#define MAX_READERS 100

#define MAX_BUF_SIZE 0x1000

/*
    Serialization format:
    name        |   #bytes
    ----------------------
    code        |   4
    nr_entries  |   4
    ////Parcel entry 1////
    type        |   4
    size        |   4
    data        |   size
    ////Parcel entry 2////
    type        |   4
    size        |   4
    data        |   size
            ...
    ////Parcel entry n////
    type        |   4
    size        |   4
    data        |   size
    ----------------------
*/

/*
    Represents one serialized piece of data in a  parcel
*/
typedef struct ParcelData {
    uint32_t type;              // data type being serialized
    unsigned char* buf;             // pointer to raw data
    uint32_t buf_size;          // size of raw data  
} ParcelData;

/* 
    Represents one parcel in the fuzz input
*/
typedef struct FuzzParcel {
    uint32_t code;                  // onTransact command Id        
    uint32_t nr_entries;            // number of serialized arguments 
    unsigned char* buf;                          // pointer to input buffer
    uint32_t buf_size;              // size of the input buffer
    uint32_t index;                 // input cursor
    ParcelData* entries[MAX_ENTRIES];   // list of parcelData entries
} FuzzParcel;  


const long special_ints[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 , 
                                    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 
                                    26, 27, 28, 29, 30, 31, 32, 60, 61, 62, 63, 64,
                                    65, 128, 256, 512, 1024, 2048, 4096, -1, -2, -3, -4,
                                    -8, -16, -32, -64, -128, -256, -512, -1024, -2048, 
                                    -4096};


static const char *special_strings[] = {
    "/data/local/tmp/test.apk",
    "8.8.8.8",
    "/asdf/test",
    "http://127.0.0.1:8080/payload",
    "https://127.0.0.1/wow",
    "http://example.com",
    "127.0.8.1",
    "69.69.69.69",
    "INPUT",
    "OUTPUT",
    "FORWARD",
    "wlan",
    "lo",
    "eth0",
    "cenc",
    "android.permission.CALL_PHONE",
    "1",
    "2",
    "3",
    "android",
    "com.android.nfc",
    "HmacSHA256",
    "2001:4860:4860::8888",
    "   ",
    "{\"wow\": 1234}",
    "android:wifi_scan",
    "android:manage_ipsec_tunnels",
    "wow=test&asdf=pls"
};

static const char* _mutate_apk_path = "/data/local/tmp/test.apk";

#define SPECIALINT_PROB 10
#define SPECIALSTRING_PROB 30

#ifdef LOCALLIB
extern "C" {
#endif
/*
    Parcel specific mutators
    if the mutation fails, return 0
*/
size_t InsertEntry(FuzzParcel* input, size_t MaxSize);
size_t DeleteEntry(FuzzParcel* input, size_t MaxSize);
size_t ShuffleEntries(FuzzParcel* input, size_t MaxSize);
size_t ChangeCmd(FuzzParcel* input, size_t MaxSize);
size_t MutateEntry(FuzzParcel* input, size_t MaxSize);

/*
    read a single integer from the input
*/
uint32_t fp_readi(FuzzParcel* input);

/*
    copy out data from the input buffer
*/
unsigned char* fp_copyb(FuzzParcel* input, uint32_t toread);

/*
    Initialize the FuzzParcel for deserialization
*/
FuzzParcel* init_fuzzparcel(uint8_t *Data, size_t Size);

/*
    Deserialize all the ParcelData from the FuzzParcel
*/
uint32_t deserialize_fuzzparcel(FuzzParcel* input);

/*
    Serialize the ParcelData object to a raw fuzzer seed
*/
size_t serialize_fuzzparcel(FuzzParcel* input, uint8_t *Data, size_t MaxSize);

/*
    Deallocate everything associated in the FuzzParcel
*/
void free_fuzzdata(ParcelData* data);
void free_fuzzparcel(FuzzParcel* input);

/*
    For mutator scheduling
*/
uint32_t select_mutator(int rand);

/*
    Callback to set LLVM default mutators
*/
void SetDefaultMutators(void* LLVMDefaultMutators, void* LLVMMutationDispatcher, void* CurrentMutators);

/*
    Callback to pass in fuzzer stats to mutator
*/
void setStats(size_t* NrRuns, size_t* NrUnitsAdded, size_t* LastCorpUp);

/*
    Make Mutator aware of the used deserialization functions
*/
void InitMutator(char* deser_used_path, char* mutator_choice);

/*
    Custom Parcel aware mutator
*/
size_t ParcelMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, uint32_t Seed);

/*
    Print information about deserialized parcel
*/
void print_info(uint8_t* Data, size_t Size);

#ifdef LOCALLIB
}
#endif

#ifndef LOCALLIB
/*
    From serialized FuzzParcel generate Parcel
*/
uint32_t create_parcel(Parcel* testcase, unsigned char* Data, size_t Size);
#endif

#endif