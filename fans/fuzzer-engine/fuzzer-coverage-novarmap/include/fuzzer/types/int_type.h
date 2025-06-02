#ifndef INT_TYPE_H
#define INT_TYPE_H
#include <arpa/inet.h>
#include <binder/Parcel.h>
#include <ctime>
#include <fuzzer/constraint_checker.h>
#include <fuzzer/dependency_solver.h>
#include <fuzzer/parcel_reader_writer.h>
#include <fuzzer/transaction.h>
#include <fuzzer/types/base_type.h>
#include <fuzzer/types/enum_type.h>
#include <fuzzer/types/int_type.h>
#include <fuzzer/utils/log.h>
#include <fuzzer/utils/random.h>
#include <fuzzer/utils/util.h>
#include <iostream>
#include <json/json.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <random>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <fuzzer/interface/camera.h>

using namespace std;

// Some potentially interesting integers.
#define specIntsLen 42
extern const uint64_t specialInts[specIntsLen];

/* Not part of public API */
// copy from
// http://androidxref.com/9.0.0_r3/xref/system/media/audio/include/system/audio.h#182
static inline uint32_t
my_audio_channel_mask_from_representation_and_bits(uint32_t representation,
                                                   uint32_t bits) {
  return ((representation << 30) | bits);
}

template <typename T> class IntType : public BaseType<T> {

  uint64_t customRandomUInt64() {
    uint64_t value = randomUInt64(0, UINT64_MAX);
    if (nOutOf(100, 182)) {
      value %= 10;
    } else if (nOutOf(50, 82)) {
      value = specialInts[randomUInt64(0, specIntsLen - 1)];
    } else if (nOutOf(10, 32)) {
      value %= 256;
    } else if (nOutOf(10, 22)) {
      value %= 4 << 10;
    } else if (nOutOf(10, 12)) {
      value %= 64 << 10;
    } else {
      value %= 1 << 31;
    }

    // second stage
    if (nOutOf(40, 107)) {
      value = -value;
    } else {
      value <<= randomUInt64(0, 63);
    }
    return value;
  }
  bool isPid(string varName, string varType) {
    if (this->varType == "pid_t") {
      return true;
    } else if (this->varName == "pid" || this->varName == "tid" ||
               this->varName.find("Pid") != string::npos) {
      return true;
    } else {
      return false;
    }
  }
  bool isUid(string varName, string varType) {
    transform(varName.begin(), varName.end(), varName.begin(), ::tolower);
    if (varType == "uid_t") {
      return true;
    } else if (varName.find("uid") != string::npos) {
      return true;
    } else {
      return false;
    }
  }
  bool isUserId(string varName) {
    transform(varName.begin(), varName.end(), varName.begin(), ::tolower);
    if (varName.find("userid") != string::npos) {
      return true;
    } else {
      return false;
    }
  }

public:
  IntType(string varName, string varType) : BaseType<T>(varName, varType) {}

  T generate() {
    value = customRandomUInt64();
    return value;
  }
  bool isNetId(string varName) {
    transform(varName.begin(), varName.end(), varName.begin(), ::tolower);
    if (varName.find("netid") != string::npos) {
      return true;
    } else if (varName.find("networkIds") != string::npos) {
      return true;
    } else {
      return false;
    }
  }
  uint64_t generateNetId() {
    int n = randomUInt64(0, 1);
    // http://androidxref.com/9.0.0_r3/xref/system/netd/server/NetworkController.cpp#53
    if (n == 0) {
      return randomUInt64(100, 65535);
    } else {
      return randomUInt64(1, 50);
    }
  }
  bool isSdkVersion(string varName) {
    transform(varName.begin(), varName.end(), varName.begin(), ::tolower);
    if (varName.find("sdkversion") != string::npos) {
      return true;
    }
    return false;
  }
  bool isSocketPort() {
    if (this->varType == "__be16" &&
        this->varName.find("port") != string::npos) {
      return true;
    } else {
      return false;
    }
  }
  unsigned short generateSocketPort() { return randomUInt64(0, 65535); }
  unsigned int generateSocketAddr() {
    string ip = to_string(randomUInt64(0, 255));
    for (int i = 0; i < 3; ++i) {
      ip += "." + to_string(randomUInt64(0, 255));
    }
    return inet_addr(ip.c_str());
  }
  unsigned short generateSinFamily() {
    int32_t flag = randomUInt64(0, 9);
    if (flag > 5) {
      return AF_INET;
    } else if (flag > 2) {
      return AF_INET6;
    } else {
      return randomUInt64(0, 45);
    }
  }

  bool isSize(string varName) {
    transform(varName.begin(), varName.end(), varName.begin(), ::tolower);
    if (varName.find("size") != string::npos ||
        varName.find("num") != string::npos ||
        varName.find("argc") != string::npos ||
        // special for _aidl_data.resizeOutVector
        varName.find("vector_size") != string::npos) {
      return true;
    } else {
      return false;
    }
  }

  static uint64_t generateSize() {
    if (IntType<int32_t>::nOutOf(5, 100)) {
      return -randomUInt64(0, 10);
    } else {
      return specialInts[randomUInt64(0, 31)];
    }
  }
  static int32_t generatePid() {
    uint32_t flag = randomUInt64(0, 9);
    int32_t value;
    if (flag < 8) {
      value = randomUInt64(0, 32768 - 1 - 1);
    } else {
      value = getpid();
    }
    return value;
  }
  static int32_t generateUid() {
    // uid = userId * 100000  + appId //single user: uid = appId
    // userId = uid / 100000
    // appId = uid % 100000

    // suppose max 10 users
    return randomUInt64(0, 10 * 100000 + 100000 - 1);
  }

  uint32_t generateChannelMask() {
    // represent can be 0 or 2
    uint32_t represent = randomUInt64(0, 1);
    if (represent == 1) {
      represent += 1;
    }
    // TODO: how to generate bits in a better way.
    uint32_t bits = 4;
    return my_audio_channel_mask_from_representation_and_bits(represent, bits);
  }
  int32_t generateSensor() {
    // http://androidxref.com/9.0.0_r3/xref/frameworks/base/core/java/android/os/BatteryStats.java#906
    // TODO: we should generate the sensor in a better way.
    int32_t r = randomUInt64(0, 4);
    if (r == 0) {
      return -1000;
    } else {
      return randomUInt64(-10000, 10000);
    }
  }
  int32_t generateMsgType() {
    int32_t r = randomUInt64(0, 12);
    if (r < 12) {
      return 1 << r;
    } else {
      return 0xFFFF;
    }
  }

  /**
   * @brief random generate v, check if v is in [0, n-1], n/outOf
   *
   * @param n
   * @param outOf
   * @return true, if value in [0, n - 1]
   * @return false, if value in [n, outOf-1]
   */
  static bool nOutOf(uint64_t n, uint64_t outOf) {
    if (n >= outOf) {
      // log here.
      FUZZER_LOGE("bad probability");
      exit(0);
    }
    uint64_t v = randomUInt64(0, outOf - 1);
    return v < n;
  }

  T value;
};

#endif // INT_TYPE_H
