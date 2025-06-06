#ifndef RANDOM_H
#define RANDOM_H
#include <ctime>
#include <iostream>
#include <random>
/**
 * @brief return a random int64 between [min,max].
 *
 * @param min
 * @param max
 * @return uint64_t
 */

extern std::mt19937_64 rng;
extern std::mt19937_64 backup_rng;

void initializeRng(unsigned int seed);
void backupRng();
uint64_t randomUInt64(uint64_t min, uint64_t max);
float randomFloat(float min, float max);
double randomDouble(double min, double max);
#endif // RANDOM_H