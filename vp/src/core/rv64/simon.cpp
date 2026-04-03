#include "simon.h"
#include <cstdint>
#include <cstring>

static inline uint64_t rotl64(uint64_t x, unsigned r) {
    return (x << r) | (x >> (WORD_SIZE - r));
}

static inline uint64_t rotr64(uint64_t x, unsigned r) {
    return (x >> r) | (x << (WORD_SIZE - r));
}

uint64_t key_schedule[MAX_ROUNDS_128_128] = {};

uint64_t z_array[] = {0b11111010001001010110000111001101111101000100101011000011100110, // z0
                      0b10001110111110010011000010110101000111011111001001100001011010, // z1
                      0b10101111011100000011010010011000101000010001111110010110110011, // z2
                      0b11011011101011000110010111100000010010001010011100110100001111, // z3
                      0b11010001111001101011011000100000010111000011001010010011101111  // z4
                    };


void init_simon_128_128(const uint8_t *key){
    uint64_t sub_keys[2] = {};

    std::memcpy(&sub_keys[0], key, 8);
    std::memcpy(&sub_keys[1], key + 8, 8);

    uint64_t z = z_array[2];
    uint64_t c = 0xFFFFFFFFFFFFFFFCULL;
    uint64_t temp1, temp2;

    key_schedule[0] = sub_keys[0];

    for(uint8_t i = 0; i < MAX_ROUNDS_128_128 - 1; i++){
        temp1 = rotr64(sub_keys[1], 3);
        temp2 = rotr64(temp1, 1);
        temp1 = temp1 ^ temp2;
        temp1 = temp1 ^ sub_keys[0];
        temp2 = c ^ ((z >> (i % 62)) & 1);
        temp1 = temp1 ^ temp2;

        sub_keys[0] = sub_keys[1];
        sub_keys[1] = temp1;
        
        key_schedule[i+1] = sub_keys[0];
    }
}


void dec_simon_128_128(const uint8_t *cipher_text, uint8_t *plain_text){
    uint64_t left, right;
    std::memcpy(&left, cipher_text, 8);
    std::memcpy(&right, cipher_text + 8, 8);

    for(int i = MAX_ROUNDS_128_128 - 1; i >= 0; i--){
        uint64_t temp = (rotl64(left, 1) & rotl64(left, 8)) ^ right ^ rotl64(left, 2);
        right = left;
        left = temp ^ key_schedule[i];
    }

    std::memcpy(plain_text, &left, 8);
    std::memcpy(plain_text + 8, &right, 8);
}

void enc_simon_128_128(const uint8_t *plain_text, uint8_t *cipher_text){
    uint64_t left, right;
    std::memcpy(&left, plain_text, 8);
    std::memcpy(&right, plain_text + 8, 8);

    for(int i = 0 ; i < MAX_ROUNDS_128_128; i++){
        uint64_t temp = (rotl64(left, 1) & rotl64(left, 8)) ^ right ^ rotl64(left, 2);
        right = left;
        left = temp ^ key_schedule[i];
    }
    
    std::memcpy(cipher_text, &left, 8);
    std::memcpy(cipher_text + 8, &right, 8);
}