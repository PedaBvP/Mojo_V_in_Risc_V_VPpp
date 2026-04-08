#include "mojov_cipher.h"

constexpr uint64_t ASYNC_MASK = 0xFFFFFFFF00000000ULL;
constexpr uint64_t SYNC_MASK  = 0x00000000FFFFFFFFULL;


uint8_t get_contract_from_ciphers(
    std::string_view sk_pem_path,
    const uint8_t* kem_ct,
    size_t kem_ct_len,
    const uint8_t* encdc_ct,
    size_t encdc_ct_len,
    uint64_t ciphers,
    data_contract_t& dc){

    std::array<unsigned char, 16> key{};

    bool ok = load_async_cipher(sk_pem_path, kem_ct, kem_ct_len, ciphers, key);

    if(!ok){
        return 3;
    }

    init_sync_cipher(key, ciphers);
    ok = load_data_contract(encdc_ct, encdc_ct_len, ciphers, dc);

    if(!ok){
        return 4;
    }

    ok = validate_contract(dc);

    if(!ok){
        return 5;
    }

    return 0;
}


bool load_async_cipher(
    std::string_view sk_pem_path,
    const uint8_t* kem_ct,
    size_t kem_ct_len,
    uint64_t ciphers,
    std::array<unsigned char, 16>& out_key){

        ciphers &= ASYNC_MASK;

        switch(ciphers){
            default:
                return ml_kem_decapsulate_to_key128(sk_pem_path.data(), kem_ct, kem_ct_len, out_key);
        }
}


void init_sync_cipher(const std::array<unsigned char, 16>& key, 
    uint64_t ciphers){
        
        ciphers &= SYNC_MASK;

        switch(ciphers){
            default:
                init_simon_128_128(key.data());
                break;
        }
}

bool load_data_contract(const uint8_t* encdc_ct,
                        size_t encdc_ct_len,
                        uint64_t ciphers,
                        data_contract_t& dc)
{
    constexpr size_t block_size = 16;
    constexpr size_t contract_size = 64;

    if (encdc_ct == nullptr) {
        return false;
    }

    if (encdc_ct_len != contract_size) {
        return false;
    }

    if ((encdc_ct_len % block_size) != 0) {
        return false;
    }

    std::array<uint8_t, contract_size> pt{};
    std::array<uint8_t, block_size> dec_block{};
    std::array<uint8_t, block_size> iv{};

    for (size_t i = 0; i < encdc_ct_len; i += block_size) {
        dec_sync(encdc_ct + i, dec_block.data(), ciphers);

        for (size_t j = 0; j < block_size; ++j) {
            pt[i + j] = dec_block[j] ^ iv[j];
        }

        std::memcpy(iv.data(), encdc_ct + i, block_size);
    }

    decode_data_contract(dc, pt.data());
    return true;
}

uint64_t mojov_load_u64_be(const unsigned char *src) {
  return ((uint64_t)src[0] << 56) |
         ((uint64_t)src[1] << 48) |
         ((uint64_t)src[2] << 40) |
         ((uint64_t)src[3] << 32) |
         ((uint64_t)src[4] << 24) |
         ((uint64_t)src[5] << 16) |
         ((uint64_t)src[6] <<  8) |
         ((uint64_t)src[7] <<  0);
}

void decode_data_contract(data_contract_t& dc, const unsigned char in[64]) {
    dc.salt = mojov_load_u64_be(in + 0);
    std::memcpy(dc.sig, in + 8, 16);
    std::memcpy(dc.sym_key_128, in + 24, 16);
    dc.contract_sig = mojov_load_u64_be(in + 40);
    dc.ciphers = mojov_load_u64_be(in + 48);
    dc.format_sel = in[56];
    std::memcpy(dc.pad, in + 57, 7);
}

void dec_sync(const uint8_t *cipher_text, uint8_t *plain_text, uint64_t ciphers){
      ciphers &= SYNC_MASK;
        switch(ciphers){
            default:
                dec_simon_128_128(cipher_text, plain_text);
                break;
        }
}

void enc_sync(const uint8_t *plain_text, const uint8_t *cipher_text, uint64_t ciphers){
    ciphers &= SYNC_MASK;
        switch(ciphers){
            default:
                enc_simon_128_128(plain_text, cipher_text);
                break;
        }
}

bool validate_contract(data_contract_t &dc){
    static const char sig_str[16+1] = "Mojo-V ver. #001";
    return (CRYPTO_memcmp(dc.sig, sig_str, 16) == 0);
}