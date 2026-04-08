#pragma once
#ifndef MOJOV_CIPHERS_H
#define MOJOV_CIPHERS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <openssl/crypto.h>

#include "ml_kem.h"
#include "mojov.h"
#include "simon.h"

uint8_t get_contract_from_ciphers(
    std::string_view sk_pem_path,
    const uint8_t* kem_ct,
    std::size_t kem_ct_len,
    const uint8_t* encdc_ct,
    std::size_t encdc_ct_len,
    uint64_t ciphers,
    data_contract_t& dc
);

bool load_async_cipher(
    std::string_view sk_pem_path,
    const uint8_t* kem_ct,
    std::size_t kem_ct_len,
    uint64_t ciphers,
    std::array<unsigned char, 16>& out_key
);

void init_sync_cipher(
    const std::array<unsigned char, 16>& key,
    uint64_t ciphers
);

bool load_data_contract(
    const uint8_t* encdc_ct,
    std::size_t encdc_ct_len,
    uint64_t ciphers,
    data_contract_t& dc
);

uint64_t mojov_load_u64_be(const unsigned char* src);

void decode_data_contract(
    data_contract_t& dc,
    const unsigned char in[64]
);

void dec_sync(
    const uint8_t* cipher_text,
    uint8_t* plain_text,
    uint64_t ciphers
);

void enc_sync(
    const uint8_t* plain_text,
    uint8_t* cipher_text,
    uint64_t ciphers
);

bool validate_contract(const data_contract_t& dc);

#endif