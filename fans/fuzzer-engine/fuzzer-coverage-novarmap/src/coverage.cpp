#include <iostream>
#include <unordered_set>
#include <fuzzer/FuzzerSHA1.h>
#include <fuzzer/utils/log.h>
#include <fstream>
#include <string>

std::unordered_set<std::string> seen_maps = {};


void reload_cov_map(const char* hashes_path){
    std::ifstream file(hashes_path);
    if (!file.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Insert each SHA-1 hex string into the unordered set
        if (!line.empty()) {
            seen_maps.insert(line);
        }
    }
    file.close();
    FUZZER_LOGI("reloaded %lu hashes from disk", seen_maps.size());
}

// add a new coverage map to the map of explored coverage maps
void add_coverage(std::string sha1, const char* hashes_path){
    FUZZER_LOGI("adding cov map hash: %s", sha1.c_str());
    seen_maps.insert(sha1);
    std::ofstream file(hashes_path, std::ios::app);
    if(!file){
        return;
    }
    file << sha1 << '\n';
    file.close();
}

// check if the coverage map has been previously seen or not
int new_coverage(unsigned char* coverage_map, int coverage_map_size, const char* hashes_path){
    std::string sha1 = fuzzer::Hash(coverage_map, (size_t)coverage_map_size);
    if(seen_maps.find(sha1) == seen_maps.end()){
        add_coverage(sha1, hashes_path);
        return 1;
    } else {
        return 0;
    }
}

