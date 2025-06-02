#ifndef BINDERLIB_H
#define BINDERLIB_H

#include <iostream>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/IBinder.h>

#ifdef ANDROID9
#include "dumpsys_diy.h"
#endif

#ifndef ANDROID9
#define B_TYPE_LARGE 0x85
enum {
  BINDER_TYPE_BINDER = B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE),
  BINDER_TYPE_HANDLE = B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE),
};
#endif

using namespace android;

class Service{
    public:
        String16 name;
        String16 iname;
        sp <IBinder> handle;
        pid_t pid;

        Service(char* name, char* interface_name){
            this->name.setTo(String16(name));
            this->iname.setTo(String16(interface_name));
        }

        int getHandle(){
            sp < IServiceManager > sm = defaultServiceManager();
            if (!sm) {
                return -1;
            }
            sp < IBinder > service = sm->checkService(this->name);
            if(!service){
                return -1;
            }
            this->handle = service;
	    /*
            String16 iname = this->handle->getInterfaceDescriptor();
            if(!iname){
                return -1;
            }
            this->iname = iname;
	    */
            return 0;
        }

        pid_t getPid(){
#ifdef ANDROID9
	  this->pid = do_get_service_pid();
#else
          this->handle->getDebugPid(&this->pid);
#endif
          return this->pid;
        }

        int transact(uint32_t cmd, Parcel* data, Parcel* reply){
            int status = this->handle->transact(cmd, *data, reply, 0);
            return status;
        }
};

status_t bytes2Parcel(Parcel* out, String16 iname, uint8_t* data, int size){
    status_t status;
    status = out->writeInterfaceToken(iname);
    if(status != 0){
        return status;
    }
    status = out->writeByteArray(size, data);
    if(status != 0){
        return status;
    }
    return status;
}

std::vector<sp<IBinder>> debugReadAllStrongBinders(Parcel* parcel) {
    std::vector<sp<IBinder>> ret;

    size_t dataSize = parcel->dataSize();
    const uint8_t* data = parcel->data();
    //printf("initPosition: %zu\n", initPosition);
    //printf("dataSize: %zu\n", dataSize);
    for(size_t i = 0; i< dataSize; i++){
        uint32_t enum_maybe = *(uint32_t*)&data[i];
        if(enum_maybe == BINDER_TYPE_BINDER || enum_maybe == BINDER_TYPE_HANDLE){
            parcel->setDataPosition(i);
            sp<IBinder> binder = parcel->readStrongBinder();
            if (binder != nullptr) ret.push_back(binder); 
        }
    }
    return ret;
}


#endif
