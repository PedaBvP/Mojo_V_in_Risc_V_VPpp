#include "mojov.h"

    bool mojov_aead_decrypt_strong(
                __uint128_t key,
                uint64_t salt,
                uint64_t c_val,
                uint64_t contract_sig,
                uint64_t tag,
                uint64_t c_metadata,
                uint64_t &out_plaintext_val,
                uint64_t &out_metadata);
	
	uint64_t key_lo(__uint128_t k);
	uint64_t key_hi(__uint128_t k);

	AeadResultStrong mojov_aead_encrypt_strong(
                __uint128_t key,
                uint64_t salt,
                uint64_t plaintext_val,
                uint64_t contract_sig,
                uint64_t metadata);

	bool mojov_aead_decrypt_fast(
                __uint128_t key,
                uint32_t salt,
                uint64_t ciphertext,
                uint32_t contract_sig,
                uint32_t tag,
                uint64_t &out_plaintext);
        
	AeadResultFast mojov_aead_encrypt_fast(
                __uint128_t key,
                uint32_t salt,
                uint64_t plaintext,
                uint32_t contract_sig);

	bool mojov_load_decrypt(
                uint64_t addr,
                uint64_t contract_sig_expected,
                MojovFormat fmt,
                uint64_t &out_val,
                uint64_t &out_metadata );

	void mojov_store_encrypted(
                uint64_t addr,
                uint64_t plaintext_val,
                uint64_t contract_sig,
                MojovFormat fmt,
                uint64_t metadata);

    void install_contract();