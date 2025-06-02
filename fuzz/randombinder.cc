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

#include "randombinder.h"


using namespace android;

int main() {
    RandomBinder* r = new RandomBinder();
    r->setReplyData((unsigned char*)"wowow", 5);
    r->setInterfaceDescriptor((unsigned char*)"ifacenameWOW\x00", 13);
    r->setReplyData((unsigned char*)"AAAAAAAAAAAAAAAAAA", 8);
    defaultServiceManager()->addService(String16("Random"), r);
    android::ProcessState::self()->startThreadPool();
    printf("RandomBinder service is now ready");
    IPCThreadState::self()->joinThreadPool();
    printf("RandomBinder service thread joined");
}
