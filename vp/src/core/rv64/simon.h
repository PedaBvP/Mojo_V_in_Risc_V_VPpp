#pragma once
#include <cstdint>

constexpr int MAX_ROUNDS_128_128 = 68;
constexpr int WORD_SIZE = 64;
constexpr int KEY_SIZE = 128;

extern uint64_t key_schedule[MAX_ROUNDS_128_128];

extern uint64_t z_array[];

void init_simon_128_128(const uint8_t *key);
void dec_simon_128_128(const uint8_t *cipher_text, uint8_t *plain_text);
void enc_simon_128_128(const uint8_t *plain_text, uint8_t *cipher_text);
