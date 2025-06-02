//use libhidlbase.so, libfmq, libhwbinder 

/*
~/Android/Sdk/ndk/28.0.12433566/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang++ -static-libstdc++ -O0 -ggdb -Iinclude hwclient.cc -o hwclient ../device/47030DLAQ0012N/lib/libbinder.so ../device/47030DLAQ0012N/lib/libcutils.so ../device/47030DLAQ0012N/lib/libfmq.so ../device/47030DLAQ0012N/lib/libhidlbase.so ../device/47030DLAQ0012N/lib/libhwbinder.so ../device/47030DLAQ0012N/lib/liblog.so ../device/47030DLAQ0012N/lib/libselinux.so ../device/47030DLAQ0012N/lib/libutils.so
*/

/*
~/Android/Sdk/ndk/28.0.12433566/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang++ -static-libstdc++ -O0 -ggdb -Iinclude hwclient.cc -o hwclient ../device/47030DLAQ0012N/lib/libbinder.so ../device/47030DLAQ0012N/lib/libcutils.so ../device/47030DLAQ0012N/lib/libfmq.so ../device/47030DLAQ0012N/lib/libhidlbase.so ../device/47030DLAQ0012N/lib/libhwbinder.so ../device/47030DLAQ0012N/lib/liblog.so ../device/47030DLAQ0012N/lib/libselinux.so ../device/47030DLAQ0012N/lib/libutils.so
*/

#include <android/hidl/manager/1.0/IServiceManager.h>
#include <android/hidl/base/1.0/IBase.h>
#include <hidl/ServiceManagement.h>
#include <hidl/HidlTransportUtils.h>
#include <hidl/HidlBinderSupport.h>
#include <hidl/Status.h>
#include <utils/Log.h>
#include <hwbinder/Parcel.h>
#include <unistd.h>

using namespace android;

int main(){
    using ::android::hidl::manager::V1_0::IServiceManager;
    using ::android::hidl::base::V1_0::IBase;
    using ::android::hardware::hidl_string;
    using Transport = IServiceManager::Transport;
    using android::hardware::details::getDescriptor;
    using ::android::hardware::Return;
    printf("pid: %d\n", getpid());
    puts("continue?");
    getchar();
    sp<IServiceManager> sm = ::android::hardware::defaultServiceManager();
    sp<IBase> pls = sm->get(::android::hardware::hidl_string("vendor.mediatek.hardware.apuware.utils@2.0::IApuwareUtils"), ::android::hardware::hidl_string("default"));
    const std::string descriptor = getDescriptor(pls.get());
    printf("descriptor: %s\n", descriptor.c_str());
    if(pls == nullptr){
        puts("hi");
    }
    sp<android::hardware::IBinder> binder = ::android::hardware::toBinder(pls);
    puts("grabbed binder");
    android::hardware::Parcel data;
    android::hardware::Parcel reply;
    data.writeInterfaceToken(descriptor.c_str());
    data.writeInt32(3);
    binder->transact(1, data, &reply, 0);
    char* out = (char*)reply.data();
    printf("out data: %p\n", out);
    printf("out data size: %zu\n", reply.dataSize());
    int status = reply.readInt32();
    sp<android::hardware::IBinder> binder2 = reply.readStrongBinder();
    android::hardware::Parcel data2;
    android::hardware::Parcel reply2;
    data2.writeInterfaceToken("vendor.qti.hardware.dsp@1.0::IDspManager");
    data2.writeInt32(3);
    binder2->transact(1, data2, &reply2, 0);
    char* out2 = (char*)reply2.data();
    printf("out2 data: %p\n", out2);
    printf("out2 data size: %zu\n", reply2.dataSize());
    int status2 = reply2.readInt32();
    printf("IDspManager request status: %d\n", status2);

    pls->ping().assertOk();
    Return<Transport> tp = sm->getTransport(::android::hardware::hidl_string("android.frameworks.cameraservice.service@2.0::ICameraService"), ::android::hardware::hidl_string("default"));
    if(tp.isOk()){
        puts("wow");
    }
}
