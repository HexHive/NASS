#include <algorithm>
#include <fuzzer/constraint_checker.h>
#include <fuzzer/transaction.h>
#include <fuzzer/types/types.h>
#include <fuzzer/utils/log.h>
#include <fuzzer/utils/random.h>
#include <iostream>
#include <stdio.h>
#include <string>
#include <json/json.h>
#include <fstream>
#include <iostream>
#include <string>
#include <random>
#include <ctime>
#include <fuzzer/FuzzerSHA1.h>
using namespace std;
map<string, bool> usedTxs;

Transaction::Transaction() {}
Transaction::Transaction(const Transaction &) {}
Transaction::Transaction(string &txName, Json::Value &txMeta,
                         uint32_t &possIdx) {
  FUZZER_LOGI("Start initing the Transaction.");
  this->txName = txName;
  // record used txs
  usedTxs[txName] = true;
  serviceName = txMeta["serviceName"].asString();
  interfaceName = txMeta["interfaceName"].asString();
  interfaceToken = txMeta["interfaceToken"].asString();
  uint32_t codeIdx = randomUInt64(0, txMeta["code"].size() - 1);
  code = txMeta["code"][codeIdx].asUInt();
  info = txMeta["possibility"][possIdx];
  dependency = txMeta["dependency"];
  variable = txMeta["variable"];
  loop = txMeta["loop"];
  constraint = txMeta["constraint"];
  flags = 1; // default async
  FUZZER_LOGD("Basic info about this transaction:");
  FUZZER_LOGD("   txName %s", txName.c_str());
  FUZZER_LOGD("   serviceName  %s", serviceName.c_str());
  FUZZER_LOGD("   interfaceName  %s", interfaceName.c_str());
  FUZZER_LOGD("   interfaceToken %s", interfaceToken.c_str());
  FUZZER_LOGD("   Code %lu", code);
}

Transaction deserialize_tx(char* file_path, std::mt19937_64& rng){
    Json::Value root;
    std::ifstream file(file_path, std::ifstream::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file!" << std::endl;
        exit(-1); 
    }
    std::string contents((std::istreambuf_iterator<char>(file)), 
    std::istreambuf_iterator<char>());
    //file.seekg(0, std::ios::beg);
    //char* buffer = new char[bufferSize];
    //file.read(buffer, bufferSize);
    Json::Reader reader;
    bool ok = reader.parse(contents.c_str(), root);
    if (!ok) {
        exit(-1);
    }
    file.close();
    Transaction tx;
    tx.txName = root["txName"].asString();
    tx.info = root["txMeta"]["info_possIdx"];
    tx.dependency = root["txMeta"]["dependency"];
    tx.variable = root["txMeta"]["variable"];
    tx.constraint = root["txMeta"]["constraint"];
    tx.loop = root["txMeta"]["loop"];
    tx.code = root["txMeta"]["code_codeIdx"].asUInt();
    tx.interfaceToken = root["txMeta"]["interfaceToken"].asString();
    tx.interfaceName = root["txMeta"]["interfaceName"].asString();
    tx.serviceName = root["txMeta"]["serviceName"].asString();

    // deserialize the rng state
    std::string rng_filename = std::string(file_path) + std::string(".rng");
    std::ifstream rng_file(rng_filename, std::ifstream::binary);
    if (!rng_file.is_open()) {
        std::cerr << "Error opening .rng file!!" << std::endl;
        exit(-1); 
    }
    rng_file >> rng;
    rng_file.close();
    return tx;
}

std::string Transaction::serialize(){
    Json::Value txMeta;
    txMeta["info_possIdx"] = this->info;
    txMeta["dependency"] = this->dependency;
    txMeta["variable"] = this->variable;
    txMeta["constraint"] = this->constraint;
    txMeta["loop"] = this->loop;
    txMeta["code_codeIdx"] = (uint32_t)this->code;
    txMeta["interfaceToken"] = this->interfaceToken;
    txMeta["interfaceName"] = this->interfaceName;
    txMeta["serviceName"] = this->serviceName;
    Json::Value serialized;
    serialized["txName"] = this->txName.c_str();
    serialized["txMeta"] = txMeta;
    return serialized.toStyledString();
}

void Transaction::dump_crashed(const char* output_dir, std::mt19937_64 rng_back){
    std::string serialized = this->serialize();
    const char* serialized_char = serialized.c_str();
    std::time_t current_time = std::time(nullptr);
    // Convert the timestamp to a string
    std::string timestamp_str = std::to_string(current_time);
    std::string sha1 = fuzzer::Hash((const uint8_t*)serialized_char, strlen(serialized_char));
    std::string out_path = std::string(output_dir) + std::string("/") + std::string("crash-") + sha1 + std::string("-") + timestamp_str;
    std::ofstream file(out_path, std::ios::out | std::ios::binary);
    file.write(serialized_char, strlen(serialized_char));
    file.close();
    // dump the rng
    std::string rng_out_path = out_path + std::string(".rng");
    std::ofstream rng_out_file(rng_out_path, std::ios::out | std::ios::binary);
    if (!rng_out_file) {
        std::cerr << "Error opening file for writing. rng: " << rng_out_path << std::endl;
        return;
    }
    // Save the state of the RNG
    rng_out_file << rng_back;
    rng_out_file.close();
}

void Transaction::dump_timeout(const char* output_dir, std::mt19937_64 rng_back){
    std::string serialized = this->serialize();
    const char* serialized_char = serialized.c_str();
    std::string sha1 = fuzzer::Hash((const uint8_t*)serialized_char, strlen(serialized_char));
    std::string out_path = std::string(output_dir) + std::string("/") + std::string("timeout-") + sha1;
    std::ofstream file(out_path, std::ios::out | std::ios::binary);
    file.write(serialized_char, strlen(serialized_char));
    file.close();
    // dump the rng
    std::string rng_out_path = out_path + std::string(".rng");
    std::ofstream rng_out_file(rng_out_path, std::ios::out | std::ios::binary);
    if (!rng_out_file) {
        std::cerr << "Error opening file for writing. rng: " << rng_out_path << std::endl;
        return;
    }
    // Save the state of the RNG
    rng_out_file << rng_back;
    rng_out_file.close();
}

void Transaction::dump_new_cov(unsigned long iteration, const char* seed_dir, std::mt19937_64 rng_back){
    std::string serialized = this->serialize();
    const char* serialized_char = serialized.c_str();
    std::time_t current_time = std::time(nullptr);
    // Convert the timestamp to a string
    std::string timestamp_str = std::to_string(current_time);
    std::string sha1 = fuzzer::Hash((const uint8_t*)serialized_char, strlen(serialized_char));
    std::string iteration_str = std::to_string(iteration);
    std::string out_path = std::string(seed_dir) + std::string("/") + iteration_str + std::string("-") + sha1 + std::string("-") + timestamp_str;
    std::ofstream file(out_path, std::ios::out | std::ios::binary);
    file.write(serialized_char, strlen(serialized_char));
    file.close();
    // dump the rng
    std::string rng_out_path = out_path + std::string(".rng");
    std::ofstream rng_out_file(rng_out_path, std::ios::out | std::ios::binary);
    if (!rng_out_file) {
        std::cerr << "Error opening file for writing. rng: " << rng_out_path << std::endl;
        return;
    }
    // Save the state of the RNG
    rng_out_file << rng_back;
    rng_out_file.close();
}

void Transaction::dumpsha1(unsigned long iteration){
    std::string sha1 = fuzzer::Hash((const uint8_t*)this->data.data(), this->data.dataSize());
    std::string out_path = std::string("./tx_data_dump/")  + sha1 + std::string("-") + std::to_string(iteration);
    std::ofstream file(out_path, std::ios::out | std::ios::binary);
    file.write("..", 2);
    file.close(); 
}