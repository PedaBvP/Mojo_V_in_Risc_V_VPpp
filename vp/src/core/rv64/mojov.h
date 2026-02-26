#pragma once

#include "core/common/instr.h"
#include "core/common/trap.h"

namespace rv64{

#define RAISE_MOJOV_SECURITY_VIOLATION(instr) raise_trap(EXC_MOJOV_SECURITY_VIOLATION, instr.data());
    // MojoV

    extern uint64_t mojov_keycfg_buf[8];
    extern uint8_t mojov_keycfg_idx;
    extern __uint128_t mojov_sym_key;
    extern uint64_t  mojov_contract_sig;
    extern uint64_t  mojov_salt;
    extern uint64_t  mojov_ciphers_active;
    extern uint8_t  mojov_format_sel;
	extern uint64_t dfHash[8];
	extern uint64_t dfHashFp[8];

    struct AeadResultFast {
		uint64_t c_val;
		uint32_t tag;
	};	

	struct AeadResultStrong {
	    uint64_t c_val;
	    uint64_t tag;
	    uint64_t c_metadata;
	};

	enum class MojovFormat : uint8_t { Fast = 0, Strong = 1, Proofcarrying = 2 };
	
	uint64_t key_lo(__uint128_t k);
	uint64_t key_hi(__uint128_t k);

	bool mojov_aead_decrypt_strong(
                __uint128_t key,
                uint64_t salt,
                uint64_t c_val,
                uint64_t contract_sig,
                uint64_t tag,
                uint64_t c_metadata,
                uint64_t &out_plaintext_val,
                uint64_t &out_metadata);
	

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


	uint32_t get_mask(Operation::Type type);

	uint32_t get_encoding_mask(Operation::Type type);

	uint64_t get_opcode_descriptor(Operation::OpId opId, Instruction instr);


	bool is_secret(uint32_t reg);

    uint64_t splitHash(uint64_t opcode_desc, uint64_t rs1, uint64_t rs2, uint64_t rs3);

	MojovFormat get_format();

    bool is_fp_op(Operation::OpId opId);
    // void init_dfHash(Operation::OpId opId);

}