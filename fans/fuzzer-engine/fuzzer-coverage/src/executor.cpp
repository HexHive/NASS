#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <binder/Binder.h>
#include <binder/Parcel.h>
#include <fuzzer/executor.h>
#include <fuzzer/service.h>
#include <fuzzer/utils/log.h>
#include <stdio.h>
status_t Executor::run(Transaction &tx) {
  NativeServiceManager nsm;
  sp<IBinder> interface = nsm.getService(tx);
  if (interface == NULL) {
    // clear tx status
    usedTxs.erase(tx.txName);
    // TODO: consider when this tx is used by some dependency.
    return 0;
  }
  FUZZER_LOGI("Start issuing transaction %s.", tx.txName.c_str());
  status_t ret = interface->transact(tx.code, tx.data, &tx.reply, tx.flags);
  FUZZER_LOGI("Transaction return status: %d.", ret);
  // clear tx status
  usedTxs.erase(tx.txName);
  return ret;
}
status_t Executor::run_cov(Transaction &tx, unsigned char* cov_map, int cov_map_size) {
  NativeServiceManager nsm;
  sp<IBinder> interface = nsm.getService(tx);
  if (interface == NULL) {
    // clear tx status
    usedTxs.erase(tx.txName);
    // TODO: consider when this tx is used by some dependency.
    return 0;
  }
  printf("Start issuing transaction code:%ld\n", tx.code);
  memset(cov_map, 0, cov_map_size); 
  msync(cov_map, cov_map_size, MS_SYNC);
  status_t ret = interface->transact(tx.code, tx.data, &tx.reply, tx.flags);
  printf("Transaction return status: %d\n", ret);
  // clear tx status
  usedTxs.erase(tx.txName);
  return ret;
}