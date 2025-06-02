#ifndef COVERAGE_H
#define COVERAGE_H

#include <string>

// reload coverage map from disk (after resuming fuzzing)
void reload_cov_map(const char* hashes_path);

// check if the coverage map has been previously seen or not
int new_coverage(unsigned char* coverage_map, int coverage_map_size, const char* hashes_path);

void add_coverage(std::string sha1, const char* hashes_path);

#endif