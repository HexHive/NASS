#ifndef RANDOMBINDER_H
#define RANDOMBINDER_H

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

class IRandomBinder : public IInterface
{
    public:
        unsigned char* interface_name = NULL;
        unsigned char* reply_data = NULL;
        size_t reply_data_len;

        static android::String16 descriptor;
        static android::sp<IRandomBinder> asInterface(const android::sp<android::IBinder>& obj);
        virtual const android::String16& getInterfaceDescriptor() const;
        virtual void setInterfaceDescriptor(unsigned char* new_name, size_t len);
        virtual void setReplyData(unsigned char* data, size_t len);
        IRandomBinder();
        virtual ~IRandomBinder();
};

#define INFO(...)            \
    do                       \
    {                        \
        printf(__VA_ARGS__); \
        printf("\n");        \
        ALOGD(__VA_ARGS__);  \
    } while (0)




android::String16 IRandomBinder::descriptor("RandomBinder");
const android::String16& IRandomBinder::getInterfaceDescriptor() const {
	INFO("getInterfaceDescriptor");
    return descriptor;
}

void IRandomBinder::setInterfaceDescriptor(unsigned char* new_name, size_t len){
    if(interface_name == NULL){
        interface_name = (unsigned char*)malloc(len+2);
    }else{
        interface_name = (unsigned char*)realloc(interface_name, len+2);
    }
    memcpy((char*)interface_name, (const char*)new_name, len);
    interface_name[len] = 0;
    descriptor.setTo(android::String16((const char*)(interface_name)));
}

void IRandomBinder::setReplyData(unsigned char* data, size_t len){
    if(reply_data == NULL){
        ALOGD("malloc with len: %ld", len);
        reply_data = (unsigned char*)malloc(len+1);
    }else{
        ALOGD("realloc with len: %ld", len);
        reply_data = (unsigned char*)realloc(reply_data, len+1);
    }
    reply_data_len = len;
    ALOGD("memcpy len: %ld", len);
    memcpy(reply_data, data, len);
}

// Client
class BpRandomBinder : public BpInterface<IRandomBinder> {
    public:
        BpRandomBinder(const sp<IBinder>& impl) : BpInterface<IRandomBinder>(impl) {}
};

android::sp<IRandomBinder> IRandomBinder::asInterface(const android::sp<android::IBinder>& obj) {
    android::sp<IRandomBinder> intr;
    if (obj != NULL) {
        intr = static_cast<IRandomBinder*>(obj->queryLocalInterface(IRandomBinder::descriptor).get());
        if (intr == NULL) {
            intr = new BpRandomBinder(obj);
        }
    }
    return intr;
}
IRandomBinder::IRandomBinder() { }
IRandomBinder::~IRandomBinder() { }

// Server
class BnRandomBinder : public BnInterface<IRandomBinder> {
    virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0);
};

status_t BnRandomBinder::onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
	if(code == 0x5f4e5446){
		return BBinder::onTransact(code, data, reply, flags);
	}
	ALOGD("onTransact, code: %d", code);
	ALOGD("reply_data size: %ld", IRandomBinder::reply_data_len);
	reply->write(reply_data, reply_data_len);
	return 0;
}

class RandomBinder : public BnRandomBinder {
};

#endif