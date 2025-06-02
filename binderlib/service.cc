
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

#include <dlfcn.h>

#ifndef ANDROID9
#define B_TYPE_LARGE 0x85
enum {
  BINDER_TYPE_BINDER = B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE),
  BINDER_TYPE_HANDLE = B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE),
};
#endif


constexpr uint8_t kCount = 128;
constexpr size_t kPosition = 104;

/*
    shared_libs: [
        "libutils",
        "libbinder",

*/


using namespace android;
extern int somefunc(String16 s1, String16 s2, String16 s3, String16 s4);

#define INFO(...)            \
    do                       \
    {                        \
        printf(__VA_ARGS__); \
        printf("\n");        \
        ALOGD(__VA_ARGS__);  \
    } while (0)

void assert_fail(const char *file, int line, const char *func, const char *expr)
{
    INFO("assertion failed at file %s, line %d, function %s:",
         file, line, func);
    INFO("%s", expr);
    abort();
}

#define ASSERT(e)                                          \
    do                                                     \
    {                                                      \
        if (!(e))                                          \
            assert_fail(__FILE__, __LINE__, __func__, #e); \
    } while (0)

class IDemo : public IInterface
{
    public:
        enum {
            ALERT = IBinder::FIRST_CALL_TRANSACTION,
            PUSH,
            ADD,
            STRONG,
            BOOLVECTOR,
            INT32VECTOR,
            CHARVECTOR,
            TWOVECS,
            FD,
            SB
        };
        // Sends a user-provided value to the service
        virtual void        push(int32_t data)          = 0;
        // Sends a fixed alert string to the service
        virtual void        alert(String16 data, String16 data2, String16 data3, String16 data4) = 0; 
        // Requests the service to perform an addition and return the result
        virtual int32_t     add(int32_t v1, int32_t v2) = 0;
        // read strong binder and interact with it
        virtual void        wowBinder(sp<IBinder>wow) = 0;
        virtual void        bvec(bool b1, bool b2) = 0;
        virtual void        i32vec(int32_t i1, int32_t t2, int32_t t3) = 0;
        virtual void        cvec(int16_t c1, int16_t c2) = 0;
        virtual void        twovec(int32_t i1, int64_t i2, int64_t i3) = 0;
        virtual void        fdshit(int fd) = 0;
        virtual void        strongb(int pls) = 0;

        DECLARE_META_INTERFACE(Demo);  // Expands to 5 lines below:
        //static const android::String16 descriptor;
        //static android::sp<IDemo> asInterface(const android::sp<android::IBinder>& obj);
        //virtual const android::String16& getInterfaceDescriptor() const;
        //IDemo();
        //virtual ~IDemo();
};

// Client
class BpDemo : public BpInterface<IDemo> {
    public:
        BpDemo(const sp<IBinder>& impl) : BpInterface<IDemo>(impl) {
            ALOGD("BpDemo::BpDemo()");
        }

        virtual void push(int32_t push_data) {
            Parcel data, reply;
            data.writeInterfaceToken(IDemo::getInterfaceDescriptor());
            data.writeInt32(push_data);

            printf("BpDemo::push parcel to be sent:\n");
            //data.print(PLOG); endl(PLOG);

            remote()->transact(PUSH, data, &reply);

            printf("BpDemo::push parcel reply:\n");
            //reply.print(PLOG); endl(PLOG);

            ALOGD("BpDemo::push(%i)", push_data);
        }

        virtual void alert(String16 s1, String16 s2, String16 s3, String16 s4) {
            Parcel data, reply;
            data.writeInterfaceToken(IDemo::getInterfaceDescriptor());
            data.writeString16(s1);
            remote()->transact(ALERT, data, &reply, IBinder::FLAG_ONEWAY);    // asynchronous call
            ALOGD("BpDemo::alert()");
        }

        virtual int32_t add(int32_t v1, int32_t v2) {
            Parcel data, reply;
            data.writeInterfaceToken(IDemo::getInterfaceDescriptor());
            data.writeInt32(v1);
            data.writeInt32(v2);
            printf("BpDemo::add parcel to be sent:\n");
            //data.print(PLOG); endl(PLOG);
            remote()->transact(ADD, data, &reply);
            ALOGD("BpDemo::add transact reply");
            //reply.print(PLOG); endl(PLOG);

            int32_t res;
            status_t status = reply.readInt32(&res);
            ALOGD("BpDemo::add(%i, %i) = %i (status: %i)", v1, v2, res, status);
            return res;
        }
        virtual void wowBinder(sp<IBinder>wow) {
            ALOGD("not imlemented....");
            Parcel data, reply;
            data.writeInterfaceToken(IDemo::getInterfaceDescriptor()); 
            data.writeStrongBinder(wow);
            remote()->transact(STRONG, data, &reply);
        }
        virtual void        bvec(bool b1, bool b2){
        }
        virtual void        i32vec(int32_t i1, int32_t t2, int32_t t3){
        }
        virtual void        cvec(int16_t c1, int16_t c2){
        }
        virtual void        twovec(int32_t i1, int64_t i2, int64_t i3){
        }
        virtual void fdshit(int fd){
        }
        virtual void strongb(int pls){
        }
};

    //IMPLEMENT_META_INTERFACE(Demo, "Demo");
    // Macro above expands to code below. Doing it by hand so we can log ctor and destructor calls.
    const android::String16 IDemo::descriptor("Demo");
    const android::String16& IDemo::getInterfaceDescriptor() const {
        return IDemo::descriptor;
    }
    android::sp<IDemo> IDemo::asInterface(const android::sp<android::IBinder>& obj) {
        android::sp<IDemo> intr;
        if (obj != NULL) {
            intr = static_cast<IDemo*>(obj->queryLocalInterface(IDemo::descriptor).get());
            if (intr == NULL) {
                intr = new BpDemo(obj);
            }
        }
        return intr;
    }
    IDemo::IDemo() { ALOGD("IDemo::IDemo()"); }
    IDemo::~IDemo() { ALOGD("IDemo::~IDemo()"); }
    // End of macro expansion

// Server
class BnDemo : public BnInterface<IDemo> {
    virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0);
};

status_t BnDemo::onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    ALOGD("BnDemo::onTransact(%i) %i", code, flags);
    data.checkInterface(this);
    //data.print(PLOG); endl(PLOG);

    switch(code) {
        case ALERT: {
            INFO("wtf");
            String16 inData1;
            String16 inData2;
            String16 inData3;
            String16 inData4;
            INFO("[WOW] ALERT 1");
            status_t s = data.readString16(&inData1);
            if(s!=0){
                return NO_ERROR;
            }
            INFO("[WOW] ALERT 2");
            status_t s2 = data.readString16(&inData2);
            if(s2!=0){
                return NO_ERROR;
            }
            INFO("[WOW] ALERT 3");
            status_t s3 = data.readString16(&inData3);
            if(s3!=0){
                return NO_ERROR;
            }
            INFO("[WOW] ALERT 4");
            status_t s4 = data.readString16(&inData4);
            if(s4!=0){
                return NO_ERROR;
            }
            alert(inData1, inData2, inData3, inData4);
            
            return NO_ERROR;
        } break;
        case PUSH: {
            int32_t inData = data.readInt32();
            ALOGD("BnDemo::onTransact got %i", inData);
            push(inData);
            ASSERT(reply != 0);
            //reply->print(PLOG); endl(PLOG);
            return NO_ERROR;
        } break;
        case ADD: {
            int32_t inV1 = data.readInt32();
            int32_t inV2 = data.readInt32();
            int32_t sum = add(inV1, inV2);
            ALOGD("BnDemo::onTransact add(%i, %i) = %i", inV1, inV2, sum);
            ASSERT(reply != 0);
            //reply->print(PLOG); endl(PLOG);
            reply->writeInt32(sum);
            INFO("reply size: %d", reply->objectsCount());
            return NO_ERROR;
        } break;
        case STRONG: {
            ALOGD("BnDemo::STRONG called...");
            sp<IBinder> wow ;
	    const uint8_t* buf = data.data();
    //printf("initPosition: %zu\n", initPosition);
    //printf("dataSize: %zu\n", dataSize);
		for(size_t i = 0; i< data.dataSize(); i++){
			uint32_t enum_maybe = *(uint32_t*)&buf[i];
			if(enum_maybe == BINDER_TYPE_BINDER || enum_maybe == BINDER_TYPE_HANDLE){
				printf("enum: %x, off: %zu\n", enum_maybe, i);
			}
		}
            int32_t status = data.readStrongBinder(&wow);
            if(status == 0){
                ALOGD("BnDemo::readStrongBinder succeeded...");
                wowBinder(wow);
                return NO_ERROR;
            }
            ALOGD("BnDemo::readStrongBinder failed...");
            return UNKNOWN_ERROR;
        } break;
	case BOOLVECTOR: {
		int32_t status;
		std::vector<bool> bv;
		//status = data.readBoolVector(&bv);
		if(status != 0){
			return UNKNOWN_ERROR;
		}
		if(bv.size()<2){
			INFO("BOOLVECTOR vector too small: %d", bv.size());
			return UNKNOWN_ERROR;
		}
		bvec(bv[0], bv[1]);
	} break;
	case INT32VECTOR: {
        return NO_ERROR;
			  } break;
	case CHARVECTOR: {
        return NO_ERROR;
			 } break;
	case TWOVECS: {
        return NO_ERROR;
	} break;
    case FD: {
        int fild = data.readFileDescriptor(); 
        INFO("FD read: %d", fild);
        fdshit(fild);
        return NO_ERROR;
    }
    case SB: {
        INFO("writing SB!");
        strongb(2);
        sp<IServiceManager> serviceManager = defaultServiceManager();
        INFO("sp svcmgr: %p", serviceManager->getInterfaceDescriptor().c_str());
        status_t s = reply->writeStrongBinder(serviceManager);
        INFO("write status: %d", s);
        INFO("reply size: %d", reply->objectsCount());
        return NO_ERROR;
    } break;
    default:
        return BBinder::onTransact(code, data, reply, flags);
    }
    
}

class Demo : public BnDemo {
    virtual void push(int32_t data) {
        INFO("Demo::push(%i)", data);
    }
    virtual void alert(String16 d1, String16 d2, String16 d3, String16 d4) {
        INFO("Demo::alert()");
        somefunc(d1,d2,d3,d4);
    }
    virtual int32_t add(int32_t v1, int32_t v2) {
        INFO("Demo::add(%i, %i) ", v1, v2);
        return v1 + v2;
    }
    virtual void wowBinder(sp<IBinder> wow) {
        Parcel data, reply;
        INFO("Demo:: wowBinder transact!");
        status_t st = wow->transact(69, data, &reply);
        if(st != 0){
            INFO("filed transact: %d\n", st);
            return;
        }
        char ret[10];
        int status = reply.read(ret, 5);
        if(status == 0){
            ALOGD("dataa 0:%d,1:%d,2:%d\n", ret[0],ret[1],ret[2]);;;
            INFO("OK read data!");
            if(ret[0] == 'A'){
                INFO("data[0] == A!");
                if(ret[1] == 'B'){
                    INFO("data[1] == B!");
                    abort();
                }
            }
        } else {
            INFO(":( failed to read data...");
        }
    }
	virtual void        bvec(bool b1, bool b2){
		INFO("Demo::bvec %d %d", b1, b2);
		if(b1){
			INFO("wow b1 true");
			if(b2){
				INFO("wow b2 true");
			}
		}
	}
        virtual void i32vec(int32_t i1, int32_t t2, int32_t t3){
		INFO("Demo::32vec %x %x %x", i1, t2, t3);
		if(i1 < 69){
			INFO("32vec i1");
			if(t2 > 42){
				INFO("wow 42");
				if(t3 == 1337){
					INFO("wow 1337");
				}
			}
		}
	}	
        virtual void        cvec(int16_t c1, int16_t c2){
		INFO("Demo::cvec %x %x", c1, c2);
	}
        virtual void        twovec(int32_t i1, int64_t i2, int64_t i3){
		INFO("Demo::twovec %x %x %lx", i1, i2, i3);
	}
    virtual void fdshit(int fd){
        char buf[100];
        memset(buf, 0, 100);
        INFO("fdshit...");
            read(fd, buf, 0x10);
            INFO("data read into buf: 0x%lx, 0x%lx", *(long*)buf, *(long*)&buf[0x8]);
    }
    virtual void strongb(int pls){
        INFO("stronb..");
    }
};



int main() {
    /*
    void *handle = dlopen("/data/local/tmp/extra_lib.so", RTLD_LAZY);
    if (handle) {
        somefunc = (somefunc_t)dlsym(handle, "_Z8somefuncN7android8String16ES0_S0_S0_");
        char *error = dlerror();
        if (error != NULL) {
            fprintf(stderr, "Error: %s\n", error);
            dlclose(handle);
            exit(EXIT_FAILURE);
        }
        printf("somefunc: %p\n", somefunc);
    }
    */
    defaultServiceManager()->addService(String16("uwb"), new Demo());
    android::ProcessState::self()->startThreadPool();
    printf("Demo service is now ready");
    IPCThreadState::self()->joinThreadPool();
    printf("Demo service thread joined");
    
}

