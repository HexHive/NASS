#include <unistd.h>
#include <algorithm> 
#include <random>    
#ifndef LOCALLIB
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <binder/IServiceManager.h>
#else
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cassert>
#endif
#include "fuzzparcel.h"
#ifndef LOCALLIB
#include "randombinder.h"
#endif

#ifndef LOCALLIB
using namespace android;
#endif

// when extending this add to end of this enum list to ensure backwards 
// compatibility with existing seeds!!!
enum ParcelType {
    BOOL,
    BYTE,
    CHAR,
    INT32,
    INT64,
    CSTRING,
    STRING8,
    STRING16,
    STRING16UTF8,
    BYTEARRAY,
    UNKNOWN,
    STRONGBINDER,
    BOOLVECTOR,
    CHARVECTOR,
    INT32VECTOR,
    INT64VECTOR,
    STRING16VECTOR,
    STRING16UTF8VECTOR,
    FILEDESCRIPTOR,
    INT32PARCEABLEARRAYLEN, // an internal type to track sizes of parceable arrays
    PARCELFILEDESCRIPTOR,
}; 

const char* ParcelTypeStrings[] = {
    "BOOL",
    "BYTE",
    "CHAR",
    "INT32",
    "INT64",
    "CSTRING",
    "STRING8",
    "STRING16",
    "STRING16UTF8",
    "BYTEARRAY",
    "UNKNOWN",
    "STRONGBINDER",
    "BOOLVECTOR",
    "CHARVECTOR",
    "INT32VECTOR",
    "INT64VECTOR",
    "STRING16VECTOR",
    "STRING16UTF8VECTOR",
    "FILEDESCRIPTOR",
    "INT32PARCEABLEARRAYLEN",
    "PARCELFILEDESCRIPTOR"
};

enum MutatorChoice {
    DEFAULT,
    CODE,
    PARCEL,
    DATA,
    NODESER
};



#ifndef LOCALLIB
sp<IRandomBinder> randomBinderImpl;
#endif

// holds the names of deserialization functions used
ParcelType parcel_read_used[MAX_READERS];
uint32_t nr_readers_used = 0;
MutatorChoice mutator_choice = DEFAULT;

struct Mutator {
    size_t (*Fn)(void* MutationDispatcher, uint8_t *Data, size_t Size, size_t Max);
    const char *None;
    const char *Name;
  };

typedef struct StrongBinderEntry{
    uint32_t InterfaceSize;
    uint32_t ReplyDataSize;
    unsigned char data[0];
}StrongBinderEntry;

typedef struct LenValData{
    uint32_t size;
    unsigned char data[0];
}LenValData;

typedef struct VarSizeArrayEntry{
    uint32_t nrEntries;
    uint32_t size;
    unsigned char data[0];
}VarySizeArrayEntry;

std::vector<Mutator>* DefaultMutators = NULL;
std::vector<Mutator>* FixedLengthMutators = NULL;
std::vector<std::string>* MutatorSequence = NULL;
void* MutationDispatcher = NULL;
uint32_t NrDefaultMutators = 0;
uint32_t NrFixedLengthMutators = 0;

// Stats
size_t* TotalNumberOfRuns = NULL;
size_t* NumberOfNewUnitsAdded = NULL;
size_t* LastCorpusUpdateRun = NULL;

uint32_t ChangeCMDGlobal = 0;
size_t NrInsertEntries = 0;
size_t NrDeleteEntries = 0;
size_t NrShuffleEntries = 0;
size_t NrChangeCmd = 0;
size_t NrMutateEntries = 0;

#define NUMFDS 10
int fds[NUMFDS];
int curr_fd = 0;

std::vector<uint32_t> CommandCodes = {};


bool __is_fixed_length(const char* mutator_name){
    if(strcmp(mutator_name, "ChangeByte") == 0){
        return true;
    }
    if(strcmp(mutator_name, "ChangeBig") == 0){
        return true;
    }
    if(strcmp(mutator_name, "ShuffleBytes") == 0){
        return true;
    }
    if(strcmp(mutator_name, "ChangeASCIIInt") == 0){
        return true;
    }
    if(strcmp(mutator_name, "ChangeBinInt") == 0){
        return true;
    }
    return false;
}


FuzzParcel* init_fuzzparcel(uint8_t *Data, size_t Size){
    
    if(Size < 8){
        LOGD("raw input data too small!\n"); // code + size needed
        return NULL;
    }

    FuzzParcel* input = (FuzzParcel*)calloc(sizeof(FuzzParcel), 1);
    LOGD("init_fuzzparcel - input allocated: %p\n", input);
    input->code = ((uint32_t*)Data)[0];
    input->nr_entries = ((uint32_t*)Data)[1];
    input->buf = Data + (2*sizeof(uint32_t));
    input->buf_size = Size - (2*sizeof(uint32_t));
    input->index = 0;
    LOGD("init_fuzzparcel - code: %d, nr_entries: %d, buffer: %p, buf_size: %d\n", 
            input->code, input->nr_entries, input->buf, input->buf_size);

    if(input->nr_entries > MAX_ENTRIES){
        printf("!!!PANIC!!! nr_entries in deserialized data exceeds MAX_ENTRIES: \
            %d, %d\n", input->nr_entries, MAX_ENTRIES);
    }
    return input;
}

ParcelData* init_parceldata(enum ParcelType type, size_t size, FuzzParcel* fp){
    ParcelData* parcel = (ParcelData*)calloc(sizeof(ParcelData), 1);
    parcel->type = type;
    parcel->buf_size = size;
    parcel->buf = (unsigned char*)malloc(size+1);
    return parcel;
}

uint32_t fp_readi(FuzzParcel* input){
    if(sizeof(uint32_t) + input->index > input->buf_size){
        printf("fp_readi trying to read out of bounds!! input->index: %d, \
            input->buf_size: %d\n", input->index, input->buf_size);
        abort();
    }
    LOGD("fp_readi reading from %p\n", input->buf+input->index);
    uint32_t iread = *(uint32_t*)(input->buf+input->index);
    input->index += sizeof(uint32_t);
    LOGD("fp_readi - iread: %d, input->index: %d\n", iread, input->index);
    return iread;
}

unsigned char* fp_copyb(FuzzParcel* input, uint32_t toread){
    if(toread + input->index > input->buf_size){
        printf("fp_copyb trying to read out of bounds!! toread: %d, input->index: %d, \
            input->buf_size: %d\n", toread, input->index, input->buf_size);
        abort();
    }
    unsigned char* buf = (unsigned char*)malloc(toread+1);
    memcpy(buf, ((char*)input->buf)+input->index, toread);
    input->index += toread;
    LOGD("fp_copy - buf: %p, new input->index: %d\n", buf, input->index);
    return buf;
}

uint32_t deserialize_fuzzparcel(FuzzParcel* input){

    uint32_t nr_entries = input->nr_entries;
    uint32_t curr_entry_index = 0;
    uint32_t parcel_data = 0;
    while(nr_entries > 0){
        
        ParcelData* parcel = (ParcelData*)calloc(sizeof(ParcelData), 1);
        parcel->type = fp_readi(input);
        parcel->buf_size = fp_readi(input);
        LOGD("deserialize_fuzzparcel 1  - type: %d, buf_size %d\n", parcel->type, parcel->buf_size);
        parcel->buf = fp_copyb(input, parcel->buf_size);

        parcel_data += parcel->buf_size;

        LOGD("deserialize_fuzzparcel 2 - type: %d, buf_size %d, buf %p\n", 
                parcel->type, parcel->buf_size, parcel->buf);

        input->entries[curr_entry_index] = parcel; 

        nr_entries -= 1;
        curr_entry_index += 1;

        if((input->buf_size - input->index) < 0){
            printf("!!PANIC!! out of bounds read in deserialize_fuzzparcel, \
                buf_size: %d, index: %d\n", input->buf_size, input->index);
            abort();
        }
    }
    return parcel_data;
}

size_t serialize_fuzzparcel(FuzzParcel* input, uint8_t *Data, size_t MaxSize){

    size_t serialized_size = 0;
    ((uint32_t*)Data)[0] = input->code;
    ((uint32_t*)Data)[1] = input->nr_entries;
    serialized_size += 2*(sizeof(uint32_t));
    Data += 2*(sizeof(uint32_t));

    for(int i=0; i<input->nr_entries; i++){
        ParcelData* parcel = input->entries[i];
        LOGD("serialize ParcelData - type: %d, buf_size: %d\n", parcel->type, parcel->buf_size);
        ((uint32_t*)Data)[0] = parcel->type;
        ((uint32_t*)Data)[1] = parcel->buf_size;
        serialized_size += 2*(sizeof(uint32_t));
        Data += 2*(sizeof(uint32_t)); 
        memcpy(Data, parcel->buf, parcel->buf_size);
        serialized_size += parcel->buf_size;
        Data += parcel->buf_size;

        if(serialized_size > MaxSize){
            printf("!!!PANIC!!! - serialized_size > MaxSize, %zu, %zu\n", serialized_size, MaxSize);
            abort();
        }
    }
    return serialized_size;
}

void free_fuzzdata(ParcelData* data){
    free(data->buf);
    free(data);
}

void free_fuzzparcel(FuzzParcel* input){
    for(int i=0; i<input->nr_entries; i++){
       ParcelData* entry = input->entries[i];
       free_fuzzdata(entry);
       input->entries[i] = NULL; 
    }    
    free(input);
}

void fuzzparcel_append(FuzzParcel* input, ParcelData* entry){
    input->entries[input->nr_entries] = entry;
    input->nr_entries++;
    input->buf_size += entry->buf_size + 2 *sizeof(int);
}

#ifndef REPLAYONLY
size_t (*ParcelMutators[])(FuzzParcel *input, size_t MaxSize) = {
    InsertEntry,
    DeleteEntry,
    ShuffleEntries,
    ChangeCmd,
    MutateEntry
};

const char *MutatorNames[NR_MUTATORS] = {
    "InsertEntry", 
    "DeleteEntry",
    "ShuffleEntries",
    "ChangeCmd",
    "MutateEntry"
};


static void __random_fill_buffer(unsigned char* buf, size_t size){
    for(int i=0; i<size; i++){
        buf[i] = rand() % 0xff;
    }
}

static size_t __mutate_fixed_length(ParcelData* entry, FuzzParcel* input, size_t MaxSize){
    //TODO: Actually use type specific mutators..
    auto M = (*FixedLengthMutators)[rand() % NrFixedLengthMutators];
    LOGD("fixed length: mutator chosen to mutate entry: %s\n", M.Name);
    size_t NewSize = M.Fn(MutationDispatcher, entry->buf, entry->buf_size, entry->buf_size);
    assert(NewSize <= entry->buf_size);
    if(NewSize == 0){
        return -1; //Mutation failed
    }
    return NewSize;
}

static size_t __mutate_var_length(ParcelData* entry, FuzzParcel* input, size_t MaxSize){
    size_t AddSize = rand() % MAX_BUF_SIZE;
    if(AddSize != 0){
        unsigned char* new_buf = (unsigned char*)realloc(entry->buf, AddSize + entry->buf_size);
        if(!new_buf){
            LOGD("failed to realloc!\n");
            return -1;
        }
        entry->buf = new_buf;
    }
    auto M = (*DefaultMutators)[rand() % NrDefaultMutators];
    LOGD("var length: mutator chosen to mutate entry: %s\n", M.Name);
    size_t NewSize = M.Fn(MutationDispatcher, entry->buf, entry->buf_size, entry->buf_size+AddSize);
    if(NewSize == 0){
        return -1; //Mutation failed
    }
    if(NewSize + (input->buf_size - entry->buf_size) + 2*sizeof(uint32_t) > MaxSize){
        return -1; //serialized size will exceed the libfuzzers maxsize
    }
    if(NewSize != entry->buf_size){
        // update the buffer sizes
        input->buf_size = input->buf_size - entry->buf_size + NewSize;
        entry->buf_size = NewSize; //change the buffer size
    }
    return NewSize;
}

static size_t __generate_special_string(ParcelData* entry, FuzzParcel* input, size_t MaxSize){
    //int choice = rand() % 7;
    char* replace_str = NULL;
    //char scratch[0x100];
    //memset(scratch, 0, sizeof(scratch));
    replace_str = (char*)special_strings[rand() % (sizeof(special_strings)/sizeof(char*))];
    LOGD("generate_special_string, chosen string: %s\n", replace_str);
    size_t NewSize = strlen(replace_str);
    if(replace_str == NULL || NewSize == 0){
        return -1;
    }
    if(NewSize + (input->buf_size - entry->buf_size) + 2*sizeof(uint32_t) > MaxSize){
        return -1; //serialized size will exceed the libfuzzers maxsize
    }
    unsigned char* new_buf = (unsigned char*)realloc(entry->buf, NewSize+10); 
    if(!new_buf){
        LOGD("failed to realloc!\n");
        return -1;
    }
    strcpy((char*)new_buf, replace_str);
    entry->buf = new_buf;
    if(NewSize != entry->buf_size){
        // update the buffer sizes
        input->buf_size = input->buf_size - entry->buf_size + NewSize;
        entry->buf_size = NewSize; //change the buffer size
    }
    return NewSize;
}

static size_t __mutate_array_fixed(ParcelData* entry, FuzzParcel* input, size_t MaxSize, size_t elementSize){
    //TODO: mutate lenght with certain probability 
    size_t ArraySizeChange = rand() % (MAX_BUF_SIZE/elementSize);    
    size_t AddSize = ArraySizeChange*elementSize;
    if(AddSize != 0){
        unsigned char* new_buf = (unsigned char*)realloc(entry->buf, AddSize + entry->buf_size);
        if(!new_buf){
            LOGD("failed to realloc!\n");
            return -1;
        }
        entry->buf = new_buf;
    }
    auto M = (*DefaultMutators)[rand() % NrDefaultMutators];
    LOGD("var length: mutator chosen to mutate entry: %s\n", M.Name);
    size_t NewSize = M.Fn(MutationDispatcher, entry->buf, entry->buf_size, entry->buf_size+AddSize);
    if(NewSize == 0){
        return -1; //Mutation failed
    }
    if(NewSize + (input->buf_size - entry->buf_size) + 2*sizeof(uint32_t) > MaxSize){
        return -1; //serialized size will exceed the libfuzzers maxsize
    }
    size_t NewArraySize;
    if(NewSize != entry->buf_size){
        // ensure new buffer size is still consistent
        // we know the new buffer is aligned correctly and has enough space
        LOGD("__mutate_array_fixed changed lenght of array, NewSize: %ld, \
            input->buf_size: %d, entry->buf_size: %d\n", NewSize, input->buf_size, entry->buf_size);
        NewArraySize = NewSize - (NewSize % elementSize);
        // update the buffer sizes
        input->buf_size = input->buf_size - entry->buf_size + NewArraySize;
        entry->buf_size = NewArraySize; //change the buffer size
        LOGD("__mutate_array_fixed buf_size NewArraySize: %zu, input->buf_size: %d, entry->buf_size: %d\n", 
            NewArraySize, input->buf_size, entry->buf_size);
    } else {
        NewArraySize = NewSize;
    }
    return NewArraySize;
}

static size_t __mutate_array_var(ParcelData* entry, FuzzParcel* input, size_t MaxSize){
    uint32_t do_mutate_size = rand() % 10;
    VarSizeArrayEntry* varEntry = (VarSizeArrayEntry*)entry->buf;
    if(do_mutate_size == 0){
        //mutate the size of the array	
        uint32_t newSize = (rand() % 42) + 1;
        LOGD("__mutate_array_var new size: %d\n", newSize);
        if(newSize == varEntry->nrEntries){
            LOGD("__mutate_array_var size is the same: newSize %d, prev size: %d\n", newSize, varEntry->nrEntries);
            return newSize;
        }
        if(newSize < varEntry->nrEntries){
            LOGD("__mutate_array_var truncating array: newSize %d, prev size: %d\n", newSize, varEntry->nrEntries);
            varEntry->nrEntries = newSize;
            uint32_t new_data_size = 0;
            uint32_t offset = 0;
            for(int i=0; i<varEntry->nrEntries; i++){
                LenValData* lvd = (LenValData*)&varEntry->data[offset]; 
                new_data_size += lvd->size;
                offset += sizeof(uint32_t) + lvd->size;
            }
            varEntry->size = new_data_size;
            return newSize;
        } else {
            //terrible logic to add new entries
            uint32_t toAdd = newSize - varEntry->nrEntries ;
            LOGD("__mutate_array_var adding %d new entries\n", toAdd);
            uint32_t* sizes = (uint32_t*)malloc(toAdd*sizeof(uint32_t));
            uint32_t sizeNew = 0;
            for(int i=0; i<toAdd; i++){
                sizes[i] = rand() % 42 + 1;
                sizeNew += sizes[i];
            }
            uint32_t new_data_size = sizeNew + varEntry->size;
            if(input->buf_size - entry->buf_size + 2*sizeof(uint32_t) + ((2+varEntry->nrEntries)*sizeof(uint32_t)+new_data_size) > MaxSize){
                free(sizes);
                return -1;
            }
            varEntry = (VarSizeArrayEntry*)realloc(varEntry, new_data_size + (2+newSize)*sizeof(uint32_t));
            uint32_t offset = sizeof(uint32_t)*varEntry->nrEntries + varEntry->size;
            for(int i=0; i<toAdd; i++){
                LenValData* lvd = (LenValData*)&varEntry->data[offset];
                LOGD("adding new var buf entry at offset: %d, %p\n", offset, lvd);
                lvd->size = sizes[i];
                __random_fill_buffer(lvd->data, sizes[i]);
                offset += sizeof(uint32_t) + lvd->size;
            }
            varEntry->nrEntries = newSize;
            varEntry->size = new_data_size;
            entry->buf = (uint8_t*)varEntry;
            entry->buf_size = (2+varEntry->nrEntries)*sizeof(uint32_t)+varEntry->size; //nrentries,size,size for each entry + overall data size
            free(sizes);
            return entry->buf_size;
        }
    } else {
        //mutate single entry
        uint32_t idx = rand() % varEntry->nrEntries;
        //TODO support changing the size of individual entries
        uint32_t offset = 0;
        LenValData* lenval_entry = (LenValData*)&varEntry->data[offset];
        for(int i=0; i<idx; i++){
            lenval_entry = (LenValData*)&varEntry->data[offset];
            offset += lenval_entry->size + sizeof(uint32_t);
        }
        uint8_t* mutate_buf = (uint8_t*)malloc(lenval_entry->size+1);
        memcpy(mutate_buf, lenval_entry->data, lenval_entry->size);
        auto M = (*DefaultMutators)[rand() % NrDefaultMutators];
        LOGD("var array mutator chosen for idx %d: %s\n", idx, M.Name);
        size_t NewSize = M.Fn(MutationDispatcher, mutate_buf, lenval_entry->size, lenval_entry->size);
        assert(NewSize <= entry->buf_size);
        if(NewSize == 0){
            return -1; //Mutation failed
        }
        memcpy(lenval_entry->data, mutate_buf, lenval_entry->size);
        free(mutate_buf);
        return NewSize;
    }
}


static void __fill_strongbinder(unsigned char* buf, uint32_t interfaceSize, 
                                    uint32_t replyDataSize){
    StrongBinderEntry* sbEntry = (StrongBinderEntry*)buf;
    sbEntry->InterfaceSize = interfaceSize; //includes the null byte
    sbEntry->ReplyDataSize = replyDataSize;
    __random_fill_buffer(sbEntry->data, interfaceSize+replyDataSize);
    // null terminate interface name
    sbEntry->data[interfaceSize-1] = 0;
}

static size_t __mutate_strongbinder(ParcelData* entry, FuzzParcel* input, size_t MaxSize) {
    StrongBinderEntry* sbEntry = (StrongBinderEntry*)entry->buf;
    // only mutate replyData, it's very unlikely mutating the interface name is helpful
    size_t AddSize = (rand() % MAX_BUF_SIZE) + 1; 
    unsigned char* mutate_buf = (unsigned char*)malloc(AddSize + sbEntry->ReplyDataSize);
    if(!mutate_buf){
        LOGD("failed to realloc!\n");
        return -1;
    }
    memcpy(mutate_buf, &sbEntry->data[sbEntry->InterfaceSize], sbEntry->ReplyDataSize);
    auto M = (*DefaultMutators)[rand() % NrDefaultMutators];
    LOGD("__mutate_strongbinder: mutator chosen to mutate entry: %s\n", M.Name);
    size_t NewSize = M.Fn(
        MutationDispatcher, mutate_buf, sbEntry->ReplyDataSize, sbEntry->ReplyDataSize+AddSize
    );
    if(NewSize == 0){
        free(mutate_buf);
        return -1; //Mutation failed
    }
    // new size of serialized data
    size_t new_entry_size = 2*sizeof(uint32_t) + sbEntry->InterfaceSize + NewSize;
    if(new_entry_size + (input->buf_size - entry->buf_size) + 2*sizeof(uint32_t) > MaxSize){
        free(mutate_buf);
        return -1; //serialized size will exceed the libfuzzers maxsize
    }
    if(NewSize != sbEntry->ReplyDataSize){
        LOGD("NewSize: %ld, sbEntry->ReplyDataSize: %d, new_entry_size: %ld\n", 
            NewSize, sbEntry->ReplyDataSize, new_entry_size);
        // update entry
        input->buf_size = input->buf_size - entry->buf_size + new_entry_size;
        entry->buf_size = entry->buf_size + NewSize - sbEntry->ReplyDataSize;
        entry->buf = (unsigned char*)realloc((void*)entry->buf, new_entry_size);
        StrongBinderEntry* sbEntryNew = (StrongBinderEntry*)entry->buf;
        sbEntryNew->ReplyDataSize = NewSize;
        memcpy(&sbEntryNew->data[sbEntryNew->InterfaceSize], mutate_buf, NewSize);
    } else {
        LOGD("NewSize: %ld, sbEntry->ReplyDataSize: %d, new_entry_size: %ld\n", 
            NewSize, sbEntry->ReplyDataSize, new_entry_size);
        // copy content from mutated buffer
        memcpy(&sbEntry->data[sbEntry->InterfaceSize], mutate_buf, NewSize);
    }
    free(mutate_buf);
    return NewSize;
}

void SetDefaultMutators(void* LLVMDefaultMutators, void* LLVMMutationDispatcher, void* CurrentMutatorSequence){
    LOGI("setting default mutators %p\n", LLVMDefaultMutators);
    MutationDispatcher = LLVMMutationDispatcher;
    DefaultMutators = static_cast<std::vector<Mutator>*>(LLVMDefaultMutators);
    MutatorSequence = static_cast<std::vector<std::string>*>(CurrentMutatorSequence);
    FixedLengthMutators = new std::vector<Mutator>();
    NrDefaultMutators = DefaultMutators->size();
    LOGI("size of DefaultMutators: %u\n", NrDefaultMutators);
    for(int i=0; i<DefaultMutators->size(); i++){
        Mutator& mutator = (*DefaultMutators)[i];
        LOGI("Mutator Name: %s\n", mutator.Name);
        if(__is_fixed_length(mutator.Name)){
            FixedLengthMutators->push_back(mutator);
            LOGI("Adding Fixed Length Mutator: %s\n", mutator.Name);
        }
    }
    NrFixedLengthMutators = FixedLengthMutators->size();
    LOGI("size of FixedLengthMutators: %u\n", NrFixedLengthMutators);
}

void setStats(size_t* NrRuns, size_t* NrUnitsAdded, size_t* LastCorpUp){
    LOGI("setStats: setting stats in mutator\n");
    TotalNumberOfRuns = NrRuns;
    NumberOfNewUnitsAdded = NrUnitsAdded;
    LastCorpusUpdateRun = LastCorpUp;
}

long PickSpecialNumber(){
    return special_ints[rand() % (sizeof(special_ints)/sizeof(long))];
}

double data_probabilities[5] = {0.01, 0.02, 0.03, 0.04, 1.0};
double parcel_probabilities[5] = {0.3, 0.6, 0.9, 0.95, 1.0};

uint32_t select_mutator(int rand){
    switch(mutator_choice){
        case DEFAULT: {
            return (uint32_t)rand % NR_MUTATORS; 
        }
        case CODE: {
            return 3;
        }
        case PARCEL: {
            double newrand = (double)rand / (double)RAND_MAX;
            LOGD("adjusted select_mutator PARCEL, rand: %f\n", newrand);
            for(int i=0; i<5; i++){
                if(newrand <= parcel_probabilities[i]){
                    return i;
                }
            }
            return 0; 
        }
        case DATA: {
            double newrand = (double)rand / (double)RAND_MAX;
            LOGD("adjusted select_mutator DATA, rand: %f\n", newrand);
            for(int i=0; i<5; i++){
                if(newrand <= data_probabilities[i]){
                    return i;
                }
            }
            return 4;
        }
        case NODESER: {
            // mutate code or entry with chance 1/2
            int choice = rand % 2;
            if(choice == 0){
                return 3; // code
            } else {
                return 4; // data mutate single unknown entry
            }
        }
        default: {
            return (uint32_t)rand % NR_MUTATORS;
        }
    }
}

size_t InsertEntry(FuzzParcel* input, size_t MaxSize){
    if(input->nr_entries >= MAX_ENTRIES){
        // should not happen, should be handled by mutator selection
        return 0;
    }
    NrInsertEntries += 1;
    // choose a data type from used deserializers
    ParcelData* entry;
    ParcelType reader_toadd = parcel_read_used[rand() % nr_readers_used];
    switch(reader_toadd){
        case BOOL: {
            if(input->buf_size + sizeof(bool) > MaxSize){
                return 0;
            }
            LOGD("[InsertEntry - readBool]\n");
            entry = init_parceldata(BOOL, sizeof(bool), input);
            bool newbool = (bool)rand();
            memcpy(entry->buf, &newbool, sizeof(bool));
            break;
        }
        case BYTE: {
            if(input->buf_size + sizeof(uint8_t) > MaxSize){
                return 0;
            }
            LOGD("[InsertEntry - readByte]\n");
            entry = init_parceldata(BYTE, sizeof(uint8_t), input);
            uint8_t newbyte = (uint8_t)rand();
            memcpy(entry->buf, &newbyte, sizeof(uint8_t));
            break;
        }
        case CHAR: {
            if(input->buf_size + sizeof(uint16_t) > MaxSize){
                return 0;
            }
            LOGD("[InsertEntry - readChar]\n");
            entry = init_parceldata(CHAR, sizeof(uint16_t), input);
            uint16_t newchar = (uint16_t)rand();
            memcpy(entry->buf, &newchar, sizeof(uint16_t));
            break;
        }
        case INT32: {
            if(input->buf_size + sizeof(uint32_t) > MaxSize){
                return 0;
            }
            LOGD("[InsertEntry - readInt32]\n");
            entry = init_parceldata(INT32, sizeof(uint32_t), input);
            uint32_t newint = (uint32_t)rand();
            memcpy(entry->buf, &newint, sizeof(uint32_t));
            break;
        }
        case INT64: {
            if(input->buf_size + sizeof(uint64_t) > MaxSize){
                return 0;
            }
            LOGD("[InsertEntry - readInt64]\n");
            entry = init_parceldata(INT64, sizeof(uint64_t), input);
            uint64_t newlong =  ((uint64_t)rand() << 32) | (uint32_t)rand();
            memcpy(entry->buf, &newlong, sizeof(uint64_t));
            break;
        }
        case CSTRING: {
            uint32_t newSize = rand() % 42 + 1; //TODO FIXME: do somethign smarter
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            } 
            LOGD("InsertEntry - CSTRING newSize: %d\n", newSize);
            entry = init_parceldata(CSTRING, newSize, input);
            __random_fill_buffer(entry->buf, newSize);
            entry->buf[newSize-1] = 0;
            break;
        }
        case STRING8: {
            uint32_t newSize = rand() % 50 + 1; //TODO FIXME: do something smarter
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - String8 newSize: %d\n", newSize);
            entry = init_parceldata(STRING8, newSize, input);
            // Something smarter to be done for String8
            __random_fill_buffer(entry->buf, newSize);
            break;
        }
        case STRING16: {
            uint32_t newSize = rand() % 50 + 1; //TODO FIXME: do something smarter
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - String16 newSize: %d\n", newSize);
            entry = init_parceldata(STRING16, newSize, input);
            // Something smarter to be done for String16?
            __random_fill_buffer(entry->buf, newSize);
            break;
        }
        case STRING16UTF8: {
            uint32_t newSize = rand() % 50 + 1; //TODO FIXME: do something smarter
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - String16UTF8 newSize: %d\n", newSize);
            entry = init_parceldata(STRING16UTF8, newSize, input);
            // Something smarter to be done for String16UTF8
            __random_fill_buffer(entry->buf, newSize);
            entry->buf[newSize-1] = 0;
            break;
        }
        case BYTEARRAY: {
            uint32_t newSize = rand() % 69 + 1; //TODO FIXME: do something smarter
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - ByteArray newSize: %d\n", newSize);
            entry = init_parceldata(BYTEARRAY, newSize, input);
            // Something smarter to be done for String16UTF8
            __random_fill_buffer(entry->buf, newSize); 
            break;
        }
        case UNKNOWN: {
            uint32_t newSize = rand() % 20 + 1; //TODO FIXME: do something smarter
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - unknown(random bytes) newSize: %d\n", newSize);
            entry = init_parceldata(UNKNOWN, newSize, input);
            __random_fill_buffer(entry->buf, newSize);
            break;
        }
        case STRONGBINDER: {
            uint32_t interfaceSize = rand() % 20 + 10;
            uint32_t replyDataSize = rand() % 69 + 1;
            // we serialize a StrongBinderFuzzParcel object into the entry->buf
            /*
                StrongBinderEntry{
                    uint32_t interfaceSize
                    uint32_t replyDataSize
                    char data[0] // contains interface and replyData
               }
            */
            uint32_t entrySize = 2 * sizeof(uint32_t) + interfaceSize + replyDataSize;
            if(input->buf_size + entrySize > MaxSize || interfaceSize + replyDataSize == 0){
                return 0;
            } 
            LOGD("InsertEntry - strongBinder, interfaceSize: %d, replyDataSize: %d\n", 
                interfaceSize, replyDataSize);
            entry = init_parceldata(STRONGBINDER, entrySize, input);
            __fill_strongbinder(entry->buf, interfaceSize, replyDataSize);
            break;
        }
        case BOOLVECTOR: {
            uint32_t vectorSize = rand() % 42 + 1;
            uint32_t newSize = vectorSize * sizeof(uint8_t); 
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - BoolVector len: %d newSize: %d\n", vectorSize, newSize);
            entry = init_parceldata(BOOLVECTOR, newSize, input); 
            __random_fill_buffer(entry->buf, newSize); 
            break;
        }
        case CHARVECTOR: {
            uint32_t vectorSize = rand() % 42 + 1;
            uint32_t newSize = vectorSize * sizeof(uint16_t); 
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - CharVector len: %d newSize: %d\n", vectorSize, newSize);
            entry = init_parceldata(CHARVECTOR, newSize, input); 
            __random_fill_buffer(entry->buf, newSize); 
            break; 
        }
        case INT32VECTOR: {
            uint32_t vectorSize = rand() % 42 + 1;
            uint32_t newSize = vectorSize * sizeof(uint32_t); 
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - CharVector len: %d newSize: %d\n", vectorSize, newSize);
            entry = init_parceldata(INT32VECTOR, newSize, input); 
            __random_fill_buffer(entry->buf, newSize); 
            break;  
        }
        case INT64VECTOR: {
            uint32_t vectorSize = rand() % 42 + 1;
            uint32_t newSize = vectorSize * sizeof(uint64_t); 
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - CharVector len: %d newSize: %d\n", vectorSize, newSize);
            entry = init_parceldata(INT32VECTOR, newSize, input); 
            __random_fill_buffer(entry->buf, newSize); 
            break;  
        }
        case STRING16UTF8VECTOR:
        case STRING16VECTOR: {
            uint32_t arr_size = rand() % 42 + 1;
            LOGD("string16 vector of size %d", arr_size);
            uint32_t data_size = 0;
            uint32_t* sizes = (uint32_t*)calloc(sizeof(uint32_t)*arr_size, 1);
            for(int i=0; i<arr_size; i++){
                sizes[i] = rand() % 42 + 1;
                data_size += sizes[i];
                LOGD("sizes[%d] = %d", i, sizes[i]);
            }
            entry = init_parceldata(STRING16VECTOR, (2+arr_size)*sizeof(uint32_t) + data_size, input);
            VarSizeArrayEntry* ventry = (VarSizeArrayEntry*)entry->buf;
            ventry->nrEntries = arr_size;
            ventry->size = data_size;
            uint32_t offset = 0;
            for(int i=0; i<arr_size; i++){
                LenValData* entry = (LenValData*)&ventry->data[offset];
                LOGD("creating new var array entry at %p, size %d", entry, sizes[i]);
                entry->size = sizes[i];
                __random_fill_buffer(entry->data, sizes[i]);
                offset += (sizeof(uint32_t) + sizes[i]);
            }
            free(sizes);
            break;
        }
        case FILEDESCRIPTOR: {
            uint32_t newSize = rand() % 69 + 1; //TODO FIXME: do something smarter
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - filedescriptor newSize: %d\n", newSize);
            entry = init_parceldata(FILEDESCRIPTOR, newSize, input);
            __random_fill_buffer(entry->buf, newSize); 
            break;
        }
        case PARCELFILEDESCRIPTOR: {
            uint32_t newSize = rand() % 69 + 1; //TODO FIXME: do something smarter
            if(input->buf_size + newSize > MaxSize || newSize == 0){
                return 0;
            }
            LOGD("InsertEntry - parcelfiledescriptor newSize: %d\n", newSize);
            entry = init_parceldata(PARCELFILEDESCRIPTOR, newSize, input);
            __random_fill_buffer(entry->buf, newSize); 
            break; 
        }
        case INT32PARCEABLEARRAYLEN:{
            // we don't change the size of parceables...
            return input->buf_size;
        }
    }
    fuzzparcel_append(input, entry);
    MutatorSequence->push_back("InsertEntry");
    return input->buf_size; 
}

size_t DeleteEntry(FuzzParcel* input, size_t MaxSize){
    if(input->nr_entries == 0){
        // should not happen, should be handled by mutator selection
        return 0;
    }   
    NrDeleteEntries += 1;
    uint32_t todelete = rand() % input->nr_entries;
    ParcelData* deleteme = input->entries[todelete];
    uint32_t deletesize = deleteme->buf_size;
    free_fuzzdata(deleteme);
    input->entries[todelete] = NULL;
    if(!(todelete == MAX_ENTRIES-1)){
        for(int i = todelete+1; i<input->nr_entries; i++){
            // for all following entries move them back by one
            if(input->entries[i] == NULL){
                input->entries[i-1] = NULL;
                break;
            }
            input->entries[i-1] = input->entries[i];
        }
    }
    input->nr_entries--;
    input->buf_size -= deletesize;
    MutatorSequence->push_back("DeleteEntry");
    return input->buf_size;
}

size_t ShuffleEntries(FuzzParcel* input, size_t MaxSize){
    if(input->nr_entries < 2){
        return 0;
    }
    NrShuffleEntries += 1;
    uint32_t i1 = rand() % input->nr_entries;
    uint32_t i2 = rand() % input->nr_entries;
    if(i1 == i2){
        return input->buf_size;
    }
    ParcelData* d1 = input->entries[i1];
    ParcelData* d2 = input->entries[i2];
    input->entries[i1] = d2;
    input->entries[i2] = d1; 
    MutatorSequence->push_back("ShuffleEntries");
    return input->buf_size;
}

uint32_t special_commands[] = {0x5f504e47, 0x5f444d50, 0x5f434d44, 0x5f4e5446,
                            0x5f4e5447, 0x5f535052, 0x5f455854, 0x5f504944, 0x5f545754, 
                            0x5f4c494b};

size_t ChangeCmd(FuzzParcel* input, size_t MaxSize){
    uint32_t code;
    if(mutator_choice == CODE){
        if(ChangeCMDGlobal < CommandCodes.size()){
            code = CommandCodes[ChangeCMDGlobal];
            ChangeCMDGlobal+=1; 
        } else {
            code = rand() % 0x00ffffff;
        }
    } else {
        if(rand() % 2 == 0){
            code = CommandCodes[rand() % CommandCodes.size()];
        } else {
            code = rand() % 0x00ffffff;
        }
    }
    
    NrChangeCmd += 1;
    input->code = code;
    LOGD("ChangeCMD new command %d\n", input->code);
    MutatorSequence->push_back("ChangeCMd");
    return input->buf_size; //adder just here to ensure we don't return 0
}

size_t MutateEntry(FuzzParcel* input, size_t MaxSize){
    // mutate a single entry
    if(input->nr_entries == 0){
        return input->buf_size;
    }
    NrMutateEntries += 1;
    uint32_t index = (uint32_t)rand() % input->nr_entries;
    ParcelData* to_mutate = input->entries[index];
    LOGD("mutating entry: %d, %s\n", index, ParcelTypeStrings[to_mutate->type]);
    switch(to_mutate->type){
        case BOOL: {
            *(bool*)to_mutate->buf = !(*(bool*)to_mutate->buf);
            MutatorSequence->push_back("SwitchBool");
            break;
        }
        case BYTE: {
            *(char*)to_mutate->buf = rand() % 0x100;
            MutatorSequence->push_back("RandomByte");
            break;
        }
        case CHAR: {
            if(rand() % SPECIALINT_PROB == 0){
                *(short*)to_mutate->buf = (short)PickSpecialNumber();
                MutatorSequence->push_back("PickSpecialNumber");
            } else {
                if(__mutate_fixed_length(to_mutate, input, MaxSize) == -1){
                    return -1;
                }
                MutatorSequence->push_back("MutateFixedLen");
            }
            break;
        }
        case INT32: {
            if(rand() % SPECIALINT_PROB == 0){
                *(int*)to_mutate->buf = (int)PickSpecialNumber();
                MutatorSequence->push_back("PickSpecialNumber");
            } else {
                if(__mutate_fixed_length(to_mutate, input, MaxSize) == -1){
                    return -1;
                }
                MutatorSequence->push_back("MutateFixedLen");
            }
            break;
        }
        case INT64: {
            if(rand() % SPECIALINT_PROB == 0){
                *(long*)to_mutate->buf = (long)PickSpecialNumber();
                MutatorSequence->push_back("PickSpecialNumber");
            } else {
                if(__mutate_fixed_length(to_mutate, input, MaxSize) == -1){
                    return -1;
                }
                MutatorSequence->push_back("MutateFixedLen");
            }
            break;
        }
        case CSTRING: 
        case STRING8: 
        case STRING16: 
        case STRING16UTF8: 
        case BYTEARRAY: {
            if(rand() % SPECIALSTRING_PROB == 0){
                if(__generate_special_string(to_mutate, input, MaxSize) == -1){
                    return -1;
                };
                MutatorSequence->push_back("GenerateSpecialString"); 
            } else {
                if(__mutate_var_length(to_mutate, input, MaxSize) == -1){
                    return -1;
                };
                MutatorSequence->push_back("MutateVarLen");
            }
            break;
        }
        case UNKNOWN: {
            if(__mutate_var_length(to_mutate, input, MaxSize) == -1){
                    return -1;
                };
            MutatorSequence->push_back("MutateVarLen");
            break;
        }
        case STRONGBINDER: {
            if(__mutate_strongbinder(to_mutate, input, MaxSize) == -1){
                return -1;
            };
            MutatorSequence->push_back("MutateStrongBinder");
            break;
        }
        case BOOLVECTOR: {
            if(__mutate_array_fixed(to_mutate, input, MaxSize, sizeof(uint8_t)) == -1){
                return -1;
            };
            MutatorSequence->push_back("MutateBoolArray");
            break;
        }
        case CHARVECTOR: {
            if(__mutate_array_fixed(to_mutate, input, MaxSize, sizeof(uint16_t)) == -1){
                return -1;
            };
            MutatorSequence->push_back("MutateCharArray");
            break; 
        }
        case INT32VECTOR: {
            if(__mutate_array_fixed(to_mutate, input, MaxSize, sizeof(uint32_t)) == -1){
                return -1;
            };
            MutatorSequence->push_back("MutateInt32Array");
            break;  
        }
        case INT64VECTOR: {
            if(__mutate_array_fixed(to_mutate, input, MaxSize, sizeof(uint64_t)) == -1){
                return -1;
            };
            MutatorSequence->push_back("MutateInt64Array");
            break;  
        }
        case STRING16VECTOR: {
            if(__mutate_array_var(to_mutate, input, MaxSize) == -1){
            return -1;
            }
            MutatorSequence->push_back("MutateString16Array");
            break;
        }
        case STRING16UTF8VECTOR: {
            if(__mutate_array_var(to_mutate, input, MaxSize) == -1){
            return -1;
            }
            MutatorSequence->push_back("MutateString16Utf8Array");
            break;
        }
        case FILEDESCRIPTOR: {
            if(__mutate_var_length(to_mutate, input, MaxSize) == -1){
                return -1;
            }; 
            MutatorSequence->push_back("MutateVarLen");
            break; 
        }
        case PARCELFILEDESCRIPTOR: {
            if(__mutate_var_length(to_mutate, input, MaxSize) == -1){
                return -1;
            }; 
            MutatorSequence->push_back("MutateVarLen");
            break;  
        }
        case INT32PARCEABLEARRAYLEN: {
            // don't change the size of a parceable array
            MutatorSequence->push_back("IgnoreParceableArraySize");
            break;
        }
    } 
    return input->buf_size;
}

size_t ParcelMutator(uint8_t *Data, size_t Size, size_t MaxSize, uint32_t Seed){
    LOGD("ParcelMutator, [stats: NrRuns: %zu, nrUnitsAdded: %zu, lastCorpusUpdate: %zu]\n", *TotalNumberOfRuns, *NumberOfNewUnitsAdded, *LastCorpusUpdateRun);
    LOGD("ParcelMutator, [stats: NrInsertEntries: %zu, NrDeleteEntries: %zu, NrShuffleEntries: %zu, NrChangeCmd: %zu, NrMutateEntries: %zu]\n", NrInsertEntries, NrDeleteEntries, NrShuffleEntries, NrChangeCmd, NrMutateEntries);
    LOGD("ParcelMutator - Size: %zu, MaxSize: %zu\n", Size, MaxSize);
    FuzzParcel* input = init_fuzzparcel(Data, Size);
    if(input == NULL){
        return 0;
    }
    deserialize_fuzzparcel(input);

    srand(Seed);
    uint32_t chosen_mutator = select_mutator(rand());
    LOGD("ParcelMutator chosen: %s\n", MutatorNames[chosen_mutator]);
    size_t new_size = ParcelMutators[chosen_mutator](input, MaxSize);
    if(new_size == -1){
        // -1 is the code that the mutator failed, return 0 size in that case
        free_fuzzparcel(input);
        return 0;
    }
    size_t serialized_size = serialize_fuzzparcel(input, Data, MaxSize);
    free_fuzzparcel(input);
    return serialized_size;
}
#endif

void InitMutator(char* deser_used_path, char* mutator_choice_param){
#ifndef REPLAYONLY
    if(strcmp(mutator_choice_param, "DATA") == 0){
        mutator_choice = DATA;
    } else if (strcmp(mutator_choice_param, "PARCEL") == 0){
        mutator_choice = PARCEL;
    } else if (strcmp(mutator_choice_param, "CODE") == 0){
        mutator_choice = CODE;
    } else  if (strcmp(mutator_choice_param, "NODESER") == 0){
        mutator_choice = NODESER;
    }
    int MAX_LINE_LENGHT = 0x1000;
    FILE* parcel_read_file = fopen(deser_used_path, "r");
    char line[MAX_LINE_LENGHT];
    while (fgets(line, sizeof(line), parcel_read_file) && nr_readers_used < MAX_READERS) {

        line[strcspn(line, "\n")] = '\0';

        if (strcmp(line, "readBool") == 0){
            parcel_read_used[nr_readers_used] = BOOL; 
        }
        else if(strcmp(line, "readByte") == 0){
            parcel_read_used[nr_readers_used] = BYTE;
        }
        else if(strcmp(line, "readChar") == 0){
            parcel_read_used[nr_readers_used] = CHAR;
        } 
        else if(strcmp(line, "readInt32") == 0){
            parcel_read_used[nr_readers_used] = INT32;
        } 
        else if(strcmp(line, "readInt64") == 0){
            parcel_read_used[nr_readers_used] = INT64;
        } 
        else if(strcmp(line, "readCString") == 0){
            parcel_read_used[nr_readers_used] = CSTRING; 
        } 
        else if(strcmp(line, "readString8") == 0){
            parcel_read_used[nr_readers_used] = STRING8;
        }
        else if(strcmp(line, "readString16") == 0){
            parcel_read_used[nr_readers_used] = STRING16; 
        } 
        else if(strcmp(line, "readUtf8FromUtf16") == 0){
            parcel_read_used[nr_readers_used] = STRING16UTF8;
        }
        else if(strcmp(line, "readByteArray") == 0){
            parcel_read_used[nr_readers_used] = BYTEARRAY;
        }
        else if(strcmp(line, "checkInterface") == 0){
            // don't consider this for now as we write the descriptor anyways
            continue;
        }
        else if(strcmp(line, "readStrongBinder")== 0){
            parcel_read_used[nr_readers_used] = STRONGBINDER;
        }
        else if(strcmp(line, "readBoolVector")== 0){
            parcel_read_used[nr_readers_used] = BOOLVECTOR;
        }
        else if(strcmp(line, "readCharVector")== 0){
            parcel_read_used[nr_readers_used] = CHARVECTOR;
        }
        else if(strcmp(line, "readInt32Vector")== 0){
            parcel_read_used[nr_readers_used] = INT32VECTOR;
        }
        else if(strcmp(line, "readInt64Vector")== 0){
            parcel_read_used[nr_readers_used] = INT64VECTOR;
        }
        else if(strcmp(line, "readString16Vector")== 0){
            parcel_read_used[nr_readers_used] = STRING16VECTOR;
        }
        else if(strcmp(line, "readUtf8VectorFromUtf16Vector")== 0){
            parcel_read_used[nr_readers_used] = STRING16UTF8VECTOR;
        }
        else if(strcmp(line, "readFileDescriptor")== 0){
            parcel_read_used[nr_readers_used] = FILEDESCRIPTOR;
        } 
        else if(strcmp(line, "readParcelFileDescriptor")== 0){
            parcel_read_used[nr_readers_used] = PARCELFILEDESCRIPTOR;
        }
        else {
            parcel_read_used[nr_readers_used] = UNKNOWN;
        }
        LOGD("line: %s\n", line);
        LOGD("deserializer used: %d, %s\n", parcel_read_used[nr_readers_used], ParcelTypeStrings[parcel_read_used[nr_readers_used]]);
        nr_readers_used++;
    }
    // fallback in case no other readers were found
    if(nr_readers_used == 0){
        LOGI("adding default readers\n");
        parcel_read_used[0] = UNKNOWN;
        parcel_read_used[1] = INT32;
        nr_readers_used += 2;
    }
    LOGI("nr deserializers used: %d\n", nr_readers_used);

    for(int i=1; i<=0x2000; i++){
        CommandCodes.push_back(i);
    }
    for(int i=0x00ffffff-0x2000; i<=0x00ffffff; i++){
        CommandCodes.push_back(i);
    }
    for(int i=0; i<10; i++){
        CommandCodes.push_back(special_commands[i]);
    }
    std::random_device rd;  // Seed for the random number generator
    std::mt19937 g(rd());   // Mersenne Twister engine seeded with rd()
    std::shuffle(CommandCodes.begin(), CommandCodes.end(), g);
#endif
    #ifndef LOCALLIB
    LOGI("initializing randomBinder...\n");
    randomBinderImpl = new RandomBinder();
    LOGI("setting up fds\n");
    system("rm -rf ./fddata");
    system("mkdir -p ./fddata");
    /*for(int i=0; i<NUMFDS; i++){
        std::string base = "./fddata";
        std::string path = base + "/" + std::to_string(i);
        const char* p_c = path.c_str();
        fds[i] = open(p_c, O_RDWR | O_CREAT);
        LOGD("new fd opened: %s, %d\n", p_c, fds[i]);
    }
    */
    #endif
}


#ifndef LOCALLIB
static void __write_to_parcel(Parcel* testcase, ParcelData* entry){
    switch(entry->type){
        case BOOL: {
            LOGD("__write_to_parcel, writing bool\n");
            testcase->writeBool(*(bool*)entry->buf);
            break;
        }
        case BYTE: {
            LOGD("__write_to_parcel, writing byte\n");
            testcase->writeByte(*(uint8_t*)entry->buf); 
            break;
        }
        case CHAR: {
            LOGD("__write_to_parcel, writing char\n");
            testcase->writeChar(*(uint16_t*)entry->buf);
            break;
        }
        case INT32: {
            LOGD("__write_to_parcel, writing int32 %x\n", *(int*)entry->buf);
            testcase->writeInt32(*(int*)entry->buf);
            break;
        }
        case INT32PARCEABLEARRAYLEN: {
            LOGD("__write_to_parcel, writing int32parceablearraylen %x\n", *(int*)entry->buf);
            testcase->writeInt32((*(int*)entry->buf));
            break;
        }
        case INT64: {
            LOGD("__write_to_parcel, writing int64\n");
            testcase->writeInt64(*(uint64_t*)entry->buf);
            break;
        }
        case CSTRING: {
            LOGD("__write_to_parcel, writing cstring\n");
            testcase->writeCString((const char*)entry->buf);
            break;
        }
        case STRING8: {
            LOGD("__write_to_parcel, writing String8\n");
            testcase->writeString8(String8((char*)entry->buf, entry->buf_size));
            break;
        }
        case STRING16: {
            LOGD("__write_to_parcel, writing String16, buf: %p, buf_size: %u\n", entry->buf, entry->buf_size);
            testcase->writeString16(String16((char*)entry->buf, entry->buf_size));
            break;
        }
        case STRING16UTF8: {
            LOGD("__write_to_parcel, writing String16UTF8\n");
            // the way we're writing String16 this should be fine
            testcase->writeString16(String16((char*)entry->buf, entry->buf_size));
            break;
        }
        case BYTEARRAY: {
            LOGD("__write_to_parcel, writing ByteArray\n");
            testcase->writeByteArray(entry->buf_size, (const uint8_t*)entry->buf);
            break;
        }
        case UNKNOWN: {
            LOGD("__write_to_parcel, writing generic byteArray\n");
            testcase->write(entry->buf, entry->buf_size);
            break;
        }
        case STRONGBINDER: {
            //setup our binder object (TODO: add support for multiple ones)
            StrongBinderEntry* sbEntry = (StrongBinderEntry*)entry->buf; 
            LOGD("__write_to_parcel: interfaceSize: %d, replyDataSize: %d\n", sbEntry->InterfaceSize, sbEntry->ReplyDataSize);
            randomBinderImpl->setInterfaceDescriptor((unsigned char*)sbEntry->data, sbEntry->InterfaceSize);
            randomBinderImpl->setReplyData(
                (unsigned char*)&sbEntry->data[sbEntry->InterfaceSize], sbEntry->ReplyDataSize
            );
            //write reference to binder into the parcel
            testcase->writeStrongBinder(RandomBinder::asBinder(randomBinderImpl));
            break;
        }
        case BOOLVECTOR: {
            LOGD("__write_to_parcel: boolean array\n");
            uint32_t arraySize = entry->buf_size / sizeof(uint8_t);
            testcase->writeInt32(arraySize);
            for(int i = 0; i<entry->buf_size; i=i+sizeof(uint8_t)){
                uint32_t v = (uint32_t)*(bool*)&entry->buf[i];
                testcase->writeInt32(v);
            }
            break;
        }
        case CHARVECTOR: {
            LOGD("__write_to_parcel: char array\n");
            uint32_t arraySize = entry->buf_size / sizeof(uint16_t);
            testcase->writeInt32(arraySize);
            for(int i = 0; i<entry->buf_size; i=i+sizeof(uint16_t)){
                uint32_t v = (uint32_t)*(uint16_t*)&entry->buf[i];
                testcase->writeInt32(v);
            }
            break;
        } 
        case INT32VECTOR: {
            LOGD("__write_to_parcel: int32 array\n");
	        uint32_t arraySize = entry->buf_size / sizeof(uint32_t);
	        testcase->writeInt32(arraySize);
            testcase->write(entry->buf, entry->buf_size);
            break;
        }
        case INT64VECTOR: {
            LOGD("__write_to_parcel: int64 array\n");
	        uint32_t arraySize = entry->buf_size / sizeof(uint64_t);
	        testcase->writeInt32(arraySize);
            testcase->write(entry->buf, entry->buf_size);
            break; 
        }
        case STRING16UTF8VECTOR: {
            LOGD("__write_to_parcel: String8 vector\n");
            VarSizeArrayEntry* ve = (VarSizeArrayEntry*)entry->buf;
            uint32_t offset = 0;
            testcase->writeInt32(ve->nrEntries);
            for(int i=0; i<ve->nrEntries; i++){
                LenValData* lvd = (LenValData*)&ve->data[offset];
                LOGD("writing String16 to parcel: %p, %d\n", lvd->data, lvd->size);
                testcase->writeString16(String16((char*)lvd->data, lvd->size));
                offset += sizeof(uint32_t) + lvd->size;
            }
            break;
        }
        case STRING16VECTOR: {
            LOGD("__write_to_parcel: String16 vector\n");
            VarSizeArrayEntry* ve = (VarSizeArrayEntry*)entry->buf;
            uint32_t offset = 0;
            testcase->writeInt32(ve->nrEntries);
            for(int i=0; i<ve->nrEntries; i++){
                LenValData* lvd = (LenValData*)&ve->data[offset];
                LOGD("writing String16 to parcel: %p, %d\n", lvd->data, lvd->size);
                testcase->writeString16(String16((char*)lvd->data, lvd->size));
                offset += sizeof(uint32_t) + lvd->size;
            }
            break;
        }
        case FILEDESCRIPTOR: {
            LOGD("__write_to_parcel, writing Filedescriptor\n");
            char fp[0x80];
            sprintf(fp, "./fddata/%d", curr_fd);
            LOGD("__write_to_parcel fd, curr fd_idx: %d, fp: %s\n", curr_fd, fp);
            int fd = open(fp, O_RDWR|O_CREAT);
            LOGD("__write_to_parcel fd, trying to write to fd: %d\n", fd);
            int s = write(fd, entry->buf, entry->buf_size);
            LOGD("__write_to_parcel fd, written %d bytes to fd: %d\n", s, fd);
            close(fd);
            fd = open(fp, O_RDONLY);
            testcase->writeFileDescriptor(fd, true); 
            curr_fd = (curr_fd + 1) % NUMFDS;
            LOGD("__write_to_parcel fd, fd index: %d\n", curr_fd);
        }
        case PARCELFILEDESCRIPTOR: {
            LOGD("__write_to_parcel, writing ParcelFiledescriptor\n");
            char fp[0x80];
            sprintf(fp, "./fddata/%d", curr_fd);
            LOGD("__write_to_parcel fd, curr fd_idx: %d, fp: %s\n", curr_fd, fp);
            int fd = open(fp, O_RDWR|O_CREAT);
            LOGD("__write_to_parcel fd, trying to write to fd: %d\n", fd);
            int s = write(fd, entry->buf, entry->buf_size);
            LOGD("__write_to_parcel fd, written %d bytes to fd: %d\n", s, fd);
            close(fd);
            fd = open(fp, O_RDONLY);
            testcase->writeParcelFileDescriptor(fd, true); 
            curr_fd = (curr_fd + 1) % NUMFDS;
            LOGD("__write_to_parcel fd, fd index: %d\n", curr_fd);
        }
    }
}

uint32_t create_parcel(Parcel* testcase, unsigned char* Data, size_t Size){

    LOGD("creating parcel from serialized data\n");
    FuzzParcel* input = init_fuzzparcel(Data, Size);
    if(input == NULL){
        return -1;
    }
    deserialize_fuzzparcel(input);
    uint32_t code = input->code;
    for(int i = 0; i<input->nr_entries; i++){
        __write_to_parcel(testcase, input->entries[i]);
    }
    free_fuzzparcel(input); 
    return code;
}
#endif

void print_info(uint8_t* Data, size_t Size){
    printf("[*] Fuzzparcel Information:\n");
    FuzzParcel* input = init_fuzzparcel(Data, Size);
    if(input == NULL){
        return;
    }
    deserialize_fuzzparcel(input);
    uint32_t code = input->code;
    printf("[+] Command Code: %d\n", code);
    for(int i = 0; i<input->nr_entries; i++){
        ParcelData* entry = input->entries[i];
        switch(entry->type){
            case BOOL: {
                printf("[+] Bool entry: %d\n", *(bool*)entry->buf);
                break;
            }
            case BYTE: {
                printf("[+] Byte entry: %hhx\n", *(uint8_t*)entry->buf);
                break;
            }
            case CHAR: {
                printf("[+] Char entry: %hx\n", *(uint16_t*)entry->buf);
                break;
            }
            case INT32: {
                printf("[+] Int32 entry: %x\n", *(uint32_t*)entry->buf);
                break;
            }
            case INT64: {
                printf("[+] Int64 entry: %lx\n", *(uint64_t*)entry->buf);
                break;
            }
            case CSTRING: {
                printf("[+] Cstring entry, len: %d\n", entry->buf_size);
                break;
            }
            case STRING8: {
                printf("[+] String8 entry, len: %d\n", entry->buf_size);
                break;
            }
            case STRING16: {
                printf("[+] String16 entry, len: %d\n", entry->buf_size);
                break;
            }
            case STRING16UTF8: {
                printf("[+] String16UTF8 entry, len: %d\n", entry->buf_size);
                break;
            }
            case BYTEARRAY: {
                printf("[+] Bytearray entry, len: %d\n", entry->buf_size);
                break;
            }
            case UNKNOWN: {
                printf("[+] Unknown entry, len: %d\n", entry->buf_size);
                break;
            } 
            case STRONGBINDER: {
                printf("[+] StrongBinder entry, len: %d\n", entry->buf_size);
                StrongBinderEntry* sbEntry = (StrongBinderEntry*)entry->buf;
                printf("[++] interface name: %s\n", sbEntry->data);
                printf("[++] data len: %d\n", sbEntry->ReplyDataSize);
                break;
            }
            case BOOLVECTOR: {
                printf("[+] BoolVector entry: len: %d\n", entry->buf_size);
                uint32_t arraySize = entry->buf_size / sizeof(uint8_t);
                printf("[++] array size: %d\n", arraySize); 
                break;
            }
            case CHARVECTOR: {
                printf("[+] CharVector entry: len: %d\n", entry->buf_size);
                uint32_t arraySize = entry->buf_size / sizeof(uint16_t);
                printf("[++] array size: %d\n", arraySize); 
                break;
            }
            case INT32VECTOR: {
                printf("[+] Int32Vector entry: len: %d\n", entry->buf_size);
                uint32_t arraySize = entry->buf_size / sizeof(uint32_t);
                printf("[++] array size: %d\n", arraySize); 
                break;
            }
            case INT64VECTOR: {
                printf("[+] Int64Vector entry: len: %d\n", entry->buf_size);
                uint32_t arraySize = entry->buf_size / (uint32_t)sizeof(uint64_t);
                printf("[++] array size: %d\n", arraySize); 
                break;
            }
            case STRING16VECTOR: {
                printf("[+] String16Vector entry: len: %d\n", entry->buf_size);
                VarSizeArrayEntry* ve = (VarSizeArrayEntry*)entry->buf;
                uint32_t offset = 0;
                printf("[++] array size: %d\n", ve->nrEntries);
                for(int i=0; i<ve->nrEntries; i++){
                    LenValData* lvd = (LenValData*)&ve->data[offset];
                    printf("[+++] entry size: %d\n", lvd->size);
                    offset += sizeof(uint32_t) + lvd->size;
                } 
                break;
            }
    	    case STRING16UTF8VECTOR: {
                printf("[+] String16Utf8Vector entry: len: %d\n", entry->buf_size);
                VarSizeArrayEntry* ve = (VarSizeArrayEntry*)entry->buf;
                uint32_t offset = 0;
                printf("[++] array size: %d\n", ve->nrEntries);
                for(int i=0; i<ve->nrEntries; i++){
                    LenValData* lvd = (LenValData*)&ve->data[offset];
                    printf("[+++] entry size: %d\n", lvd->size);
                    offset += sizeof(uint32_t) + lvd->size;
                } 
                break;
	        }
            case FILEDESCRIPTOR: {
                printf("[+] filedescriptor entry: len: %d\n", entry->buf_size);
                break;
            }
            case PARCELFILEDESCRIPTOR: {
                printf("[+] parcelfiledescriptor entry: len: %d\n", entry->buf_size);
                break;
            }
            case INT32PARCEABLEARRAYLEN: {
                printf("[+] parcelbearraylen\n");
                break;
            }
        } 
    }
    free_fuzzparcel(input); 
}
