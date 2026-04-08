#pragma once

#ifndef ML_KEM_H
#define ML_KEM_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

EVP_PKEY* ml_kem_read_privkey_pem(const char* path);

bool ml_kem_sha256_bytes(const unsigned char* in,
                         std::size_t inlen,
                         std::array<unsigned char, 32>& out32);

bool ml_kem_hkdf_sha256_key128(const unsigned char* ss,
                               std::size_t ss_len,
                               std::array<unsigned char, 16>& key_out);

bool ml_kem_decapsulate_shared_secret(const char* sk_pem_path,
                                      const unsigned char* kem_ct,
                                      std::size_t kem_ct_len,
                                      std::vector<unsigned char>& out_ss);

bool ml_kem_decapsulate_to_key128(const char* sk_pem_path,
                                  const unsigned char* kem_ct,
                                  std::size_t kem_ct_len,
                                  std::array<unsigned char, 16>& out_key);

#endif