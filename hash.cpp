#include "hash.h"

// 哈希函数1
uint64_t hash1(uint32_t x) {
    return (x * 0xC6A4A7935BD1E995ULL) ^ (x >> 16);
}

// 哈希函数2
uint64_t hash2(uint32_t x) {
    return (x * 0xB16A3A4D6C5E15F7ULL) ^ (x >> 8);
}

// 哈希函数3
uint64_t hash3(uint32_t x)
{
    return (x << 21) ^ (x >> 21) ^ (x * 0x9E3779B97F4A7C15ULL);
}

// 哈希函数4
uint64_t hash_combined(uint32_t x, int i)
{
    return (hash1(x) + i * hash2(x)) ^ hash3(x);
}