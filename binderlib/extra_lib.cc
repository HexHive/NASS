#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <utils/RefBase.h>
#include <utils/Log.h>
#include <binder/TextOutput.h>

#include <binder/IInterface.h>
#include <binder/IBinder.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>
using namespace android;

#define INFO(...)            \
    do                       \
    {                        \
        printf(__VA_ARGS__); \
        printf("\n");        \
        ALOGD(__VA_ARGS__);  \
    } while (0)

int somefunc(String16 s1, String16 s2, String16 s3, String16 s4){
    if(s1.startsWith(String16("w"))){
        INFO("somefunc: w");
                if(s2.startsWith(String16("o"))){
                    INFO("somefunc: wo");
                    if(s3.startsWith(String16("w"))){
                        INFO("somefunc: wow");
                        if(s4.startsWith(String16("!"))){
                            INFO("somefunc: wow!");
                                abort();
                        }
                    }
                }
            }
    return 0;
}