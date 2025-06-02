#include <stdio.h>
#include <fuzzer/utils/random.h>

std::mt19937_64 rng;
std::mt19937_64 backup_rng;

using namespace std;
/**
 * @brief return a random int64 between [min,max].
 *
 * @param min
 * @param max
 * @return uint64_t
 */

void initializeRng(unsigned int seed){
    rng.seed(seed);
}

void backupRng(){
    backup_rng = rng;
}

uint64_t randomUInt64(uint64_t min, uint64_t max) {
  uniform_int_distribution<uint64_t> u(min, max);
  uint64_t out = u(rng);
  return out;
}

float randomFloat(float min, float max) {
  uniform_real_distribution<float> u(min, max);
  return u(rng);
}

double randomDouble(double min, double max) {
  uniform_real_distribution<double> u(min, max);
  return u(rng);
}