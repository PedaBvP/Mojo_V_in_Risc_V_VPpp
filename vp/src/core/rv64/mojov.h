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
	
        struct AeadResultFast {
	  	uint64_t c_val;
	  	uint32_t tag;
	};	

	struct AeadResultStrong {
	    uint64_t c_val;
	    uint64_t tag;
	    uint64_t c_metadata;
	};

	enum class MojovFormat : uint8_t { Fast = 0, Strong = 1 };
}