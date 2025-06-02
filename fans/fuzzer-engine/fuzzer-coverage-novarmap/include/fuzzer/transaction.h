#ifndef TRANSACTION_H
#define TRANSACTION_H
#include <binder/Parcel.h>
#include <json/json.h>
#include <random>
#include <string>
#include <vector>
using namespace std;
using namespace android;
class Transaction {
public:
  string txName;
  string serviceName;
  string interfaceName;
  string interfaceToken;
  uint64_t code;
  Json::Value info;
  Json::Value dependency;
  Json::Value variable;
  Json::Value constraint;
  Json::Value loop;
  Parcel data;
  Parcel reply;
  uint64_t flags;
  status_t ret;

  // vector<Transaction> txSeq;
  Transaction();
  Transaction(const Transaction &);
  Transaction(string &txName, Json::Value &txMeta, uint32_t &possIdx);
  std::string serialize();
  void dump_timeout(const char* output_dir, std::mt19937_64 rng_back);
  void dump_crashed(const char* output_dir, std::mt19937_64 rng_back);
  void dump_new_cov(unsigned long iteration, const char* seed_dir, std::mt19937_64 rng_back);
  void dumpsha1(unsigned long iteration);
};
Transaction deserialize_tx(char* file_path, std::mt19937_64& rng);
extern map<string, bool> usedTxs;
#endif // TRANSACTION_H
