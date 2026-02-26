#include "mojov.h"
#include "iss.h"

namespace rv64{

    using Operation::Type;
    using Operation::OpId;

    uint64_t mojov_keycfg_buf[8] = {0};
    uint8_t  mojov_keycfg_idx = 0;
    __uint128_t mojov_sym_key = 0;
    uint64_t mojov_contract_sig = 0;
    uint64_t mojov_salt = 0;
    uint64_t mojov_ciphers_active = 0;
    uint8_t mojov_format_sel = 0;
    uint64_t dfHash[8] = {0};
	uint64_t dfHashFp[8] = {0};



    uint64_t key_lo(__uint128_t k) {
        return static_cast<uint64_t>(k);
    }

    uint64_t key_hi(__uint128_t k) {
        return static_cast<uint64_t>(k >> 64);
    }

    void ISS::install_contract() {
        uint128_t sig = (uint128_t)mojov_keycfg_buf[0] | ((uint128_t)mojov_keycfg_buf[1] << 64);
        uint8_t sig_bytes[16];
        memcpy(sig_bytes, &sig, 16);

        uint128_t sym_key_128 = (uint128_t)mojov_keycfg_buf[2] | ((uint128_t)mojov_keycfg_buf[3] << 64);
        uint64_t contract_sig = mojov_keycfg_buf[4];
        uint64_t salt         = mojov_keycfg_buf[5];
        uint64_t ciphers      = mojov_keycfg_buf[6];
        uint8_t  format_sel   = (uint8_t)(mojov_keycfg_buf[7] & 0xFF);

        bool correct_sig = memcmp(sig_bytes, "Mojo-V ver. #001", 16) == 0;
        bool correct_ciphers = (__builtin_popcountll(ciphers) == 2); // && ((ciphers & csrs.mojov_ciphers.reg.val) == ciphers)
        bool correct_format_sel = format_sel == 0x0 || format_sel == 0x1 || format_sel == 0x2;


        if (!correct_sig || !correct_ciphers || !correct_format_sel) {
        csrs.mojov_cfg.reg.fields.key_valid = 0;
        csrs.mojov_cfg.reg.fields.mojov_en  = 0;
        RAISE_MOJOV_SECURITY_VIOLATION(instr);
        return;
        }

        csrs.mojov_cfg.reg.fields.format_sel = format_sel;
        csrs.mojov_cfg.reg.fields.key_valid = 1;
        set_csr_value(rv64::csr::MOJOV_CFG_ADDR, 0x0);

        mojov_sym_key = sym_key_128;
        mojov_contract_sig = contract_sig;
        mojov_salt = salt;
        mojov_ciphers_active = ciphers;
        mojov_format_sel = format_sel;
    }

    void ISS::mojov_store_encrypted(
        uint64_t addr,
        uint64_t plaintext_val,
        uint64_t contract_sig,
        MojovFormat fmt,
        bool fp)
    {
        // 128-bit alignment
        if (addr & 0xF) { RAISE_MOJOV_SECURITY_VIOLATION(instr); return; }

        const uint128_t key = mojov_sym_key;
        switch (fmt) {
            case MojovFormat::Fast: {
                // salt 32-bit, tag 32-bit, total 16 bytes
                const uint32_t salt = 0x123456;
            
                const auto out = mojov_aead_encrypt_fast(key, salt, plaintext_val,
                                                        static_cast<uint32_t>(contract_sig));
                lscache.store_double(addr + 0, out.c_val);
                lscache.store_word(addr + 8, salt);
                lscache.store_word(addr + 12, out.tag);
                return;
            }

            case MojovFormat::Strong: {
                // salt 64-bit, tag 64-bit, metadata 64-bit, total 32 bytes
                const uint64_t salt = 0x123456;
                
                const auto out = mojov_aead_encrypt_strong(key, salt, plaintext_val,
                                                        contract_sig, 0x0);
                lscache.store_double(addr + 0,  out.c_val);
                lscache.store_double(addr + 8,  salt);
                lscache.store_double(addr + 16, out.tag);
                lscache.store_double(addr + 24, out.c_metadata);
                return;
            }

            case MojovFormat::Proofcarrying:{
                uint64_t dfHash_val;
                
                if(fp){
                    dfHash_val = dfHashFp[instr.rs2() - 0x18];
                }else{
                    dfHash_val = dfHash[instr.rs2() - 0x18];
                }

                
                const uint64_t salt = 0x123456;
                const auto out = mojov_aead_encrypt_strong(key, salt, plaintext_val,
                                                        contract_sig, dfHash_val);
                lscache.store_double(addr + 0,  out.c_val);
                lscache.store_double(addr + 8,  salt);
                lscache.store_double(addr + 16, out.tag);
                lscache.store_double(addr + 24, out.c_metadata);
                return;
            }
        }
    }

    bool ISS::mojov_load_decrypt(
        uint64_t addr,
        uint64_t contract_sig_expected,
        MojovFormat fmt,
        uint64_t &out_val,
        bool fp)
    {
        if (addr & 0xF) return false;

        const uint128_t key = mojov_sym_key;

        switch (fmt) {
            case MojovFormat::Fast: {
                const uint64_t low  = lscache.load_double(addr + 0);
                const uint64_t high = lscache.load_double(addr + 8);
                const uint32_t salt = uint32_t(high & 0xFFFFFFFFu);
                const uint32_t tag  = uint32_t(high >> 32);

                
                uint64_t val;
                const bool ok = mojov_aead_decrypt_fast(key, salt, low,
                                                        static_cast<uint32_t>(contract_sig_expected),
                                                        tag, val);
                if (!ok) return false;
                out_val = val;
                return true;
            }

            case MojovFormat::Strong: {
                const uint64_t c_val      = lscache.load_double(addr + 0);
                const uint64_t salt       = lscache.load_double(addr + 8);
                const uint64_t tag        = lscache.load_double(addr + 16);
                const uint64_t c_metadata = lscache.load_double(addr + 24);

                uint64_t val, meta;
                
                const bool ok = mojov_aead_decrypt_strong(key, salt, c_val,
                                                        contract_sig_expected, tag,
                                                        c_metadata, val, meta);
                if (!ok) return false;
                out_val = val;
                return true;
            }

            case MojovFormat::Proofcarrying: {
                const uint64_t c_val      = lscache.load_double(addr + 0);
                const uint64_t salt       = lscache.load_double(addr + 8);
                const uint64_t tag        = lscache.load_double(addr + 16);
                const uint64_t c_metadata = lscache.load_double(addr + 24);

                uint64_t val, meta;
                const bool ok = mojov_aead_decrypt_strong(key, salt, c_val,
                                                        contract_sig_expected, tag,
                                                        c_metadata, val, meta);
                if (!ok) return false;
                out_val = val;
                
                if(fp){
                    dfHashFp[instr.rd()-0x18] = meta;
                }else{
                    dfHash[instr.rd()-0x18] = meta;
                }

                return true;
            }
        }
        return false;
    }


    AeadResultFast mojov_aead_encrypt_fast(
            uint128_t key,
            uint32_t salt,
            uint64_t plaintext,
            uint32_t contract_sig)
    {
        uint64_t k0 = key_lo(key);
        uint64_t k1 = key_hi(key);

        uint64_t c = plaintext ^ k0 ^ (uint64_t)salt;
        uint32_t t = (uint32_t)((c ^ (uint64_t)contract_sig ^ k1) & 0xffffffffu);

        return { c, t };
    }

    bool mojov_aead_decrypt_fast(
            uint128_t key,
            uint32_t salt,
            uint64_t ciphertext,
            uint32_t contract_sig,
            uint32_t tag,
            uint64_t &out_plaintext)
    {
        uint64_t k0 = key_lo(key);
        uint64_t k1 = key_hi(key);

        uint32_t expected =
            (uint32_t)((ciphertext ^ (uint64_t)contract_sig ^ k1) & 0xffffffffu);

        if (expected != tag)
            return false;

        out_plaintext = ciphertext ^ k0 ^ (uint64_t)salt;
        return true;
    }


    AeadResultStrong mojov_aead_encrypt_strong(
            uint128_t key,
            uint64_t salt,
            uint64_t plaintext_val,
            uint64_t contract_sig,
            uint64_t metadata)
    {
        uint64_t k0 = key_lo(key);
        uint64_t k1 = key_hi(key);

        uint64_t c_val      = plaintext_val ^ k0 ^ salt;
        uint64_t c_metadata = metadata      ^ k1 ^ (salt << 1);

        uint64_t tag =
            c_val
            ^ c_metadata
            ^ salt
            ^ contract_sig
            ^ k0
            ^ (k1 << 1);

        return { c_val, tag, c_metadata };
    }

    bool mojov_aead_decrypt_strong(
            uint128_t key,
            uint64_t salt,
            uint64_t c_val,
            uint64_t contract_sig,
            uint64_t tag,
            uint64_t c_metadata,
            uint64_t &out_plaintext_val,
            uint64_t &out_metadata)
    {
        uint64_t k0 = key_lo(key);
        uint64_t k1 = key_hi(key);

        uint64_t expected =
            c_val
            ^ c_metadata
            ^ salt
            ^ contract_sig
            ^ k0
            ^ (k1 << 1);

        if (expected != tag)
            return false;

        out_plaintext_val = c_val      ^ k0 ^ salt;
        out_metadata      = c_metadata ^ k1 ^ (salt << 1);

        return true;
    }


    uint32_t get_mask(Operation::Type type){
        switch(type){
            case(Type::R):
                return 0b11111110000000000111000001111111;
            case(Type::I):
            case(Type::S):
                return 0b00000000000000000111000001111111;
            case(Type::B):
            case(Type::U):
            case(Type::J):
                return 0b00000000000000000000000001111111;
            case(Type::R4):
                return 0b00000110000000000111000001111111;
            default:
                return 0b00000000000000000000000000000000;
        }
    }

    uint32_t get_encoding_mask(Type type){
        switch(type){
            case(Type::R):
                return 0b11111110000000000111000001111111;
            case(Type::R4):
                return 0b11111110000000000111000001111111;
            case(Type::I):
                return 0b11111111111100000111000001111111;
            case(Type::S):
            case(Type::B):
                return 0b11111110000000000111111111111111;
            case(Type::U):
            case(Type::J):
                return 0b11111111111111111111000001111111;
            default:
                return 0b00000000000000000000000000000000;
        }
    }

	uint64_t get_opcode_descriptor(OpId opId, Instruction instr){
        Type type = getType(opId);
        uint32_t mask = get_mask(type);
        uint32_t encoding = mask & instr.data();
        if(opId == Operation::LDE || opId == Operation::SDE || opId == Operation::FLDE || opId == Operation::FSDE){
            return ((uint64_t)mask >> 32) | encoding;
        }

        uint32_t encoding_mask = get_encoding_mask(type);
        return ((uint64_t)mask >> 32) | (encoding_mask & instr.data());
    }

    
	bool is_secret(uint32_t reg){
        return 24 <= reg && reg <= 31;
    }

    uint64_t ISS::reg_value(uint32_t reg){
        if(is_secret(reg)){
            return dfHash[(reg-0x18)];
        }
        return regs[reg];
    }

    uint64_t ISS::fpReg_value(uint32_t reg){
        if(is_secret(reg)){
            return dfHashFp[(reg-0x18)];
        }
        return  fp_regs.f64(reg).v;
    }
    
	void ISS::get_reg_values(Type type, uint64_t &rs1, uint64_t &rs2)
    {
        switch(type){
            case(Type::R):
            case(Type::S):
            case(Type::B):
                rs1 = reg_value(instr.rs1());
                rs2 = reg_value(instr.rs2());
                break;
            case(Type::I):
                rs1 = reg_value(instr.rs1());
                break;
            default:
                rs1 = 0x0;
                rs2 = 0x0;
        }
    }

    void ISS::get_fpReg_values(Type type, uint64_t &rs1, uint64_t &rs2, uint64_t &rs3)
    {
        switch(type){
            case(Type::R):
            case(Type::S):
            case(Type::B):
                rs1 = fpReg_value(instr.rs1());
                rs2 = fpReg_value(instr.rs2());
                break;
            case(Type::I):
                rs1 = fpReg_value(instr.rs1());
                break;
            case(Type::R4):
                rs1 = fpReg_value(instr.rs1());
                rs2 = fpReg_value(instr.rs2());
                rs3 = fpReg_value(instr.rs3());
                break;
            default:
                rs1 = 0x0;
                rs2 = 0x0;
                rs3 = 0x0;
        }
    }

    uint64_t splitHash(uint64_t opcode_desc, uint64_t rs1, uint64_t rs2, uint64_t rs3){
        return opcode_desc ^ rs1 ^ rs2 ^ rs3;
    }


    void ISS::calc_dfhash(OpId opId){
        if((!is_secret(instr.rd()) || mojov_format_sel != 0x2)){
            return;
        }

        Type type = getType(opId);
        bool is_fp = is_fp_op(opId);
        uint32_t pReg = instr.rd() - 0x18;
        uint64_t rs1 = 0x0;
        uint64_t rs2 = 0x0;
        uint64_t rs3 = 0x0;

        if(is_fp){
            get_fpReg_values(type, rs1, rs2, rs3);
        }else{
            get_reg_values(type, rs1, rs2);
        }



        uint64_t opcode_desc = get_opcode_descriptor(opId, instr);

        uint64_t dfHash_val = splitHash(opcode_desc, rs1, rs2, rs3);

        if(is_fp){
            dfHashFp[pReg] = dfHash_val;
        }else{
            dfHash[pReg] = dfHash_val;
        }
    }

    // void init_dfHash(OpId opId){
    //     currOpId = opId;
    // }

    MojovFormat get_format(){
        switch(mojov_format_sel){
            case(0x0):
                return MojovFormat::Fast;
            case(0x1):
                return MojovFormat::Strong;
            case(0x2):
                return MojovFormat::Proofcarrying;
            default:
                return MojovFormat::Fast;
        }
    }


    bool is_fp_op(OpId opId){
        switch(opId){
            // RV32Zfh standard extension
            case Operation::FLH:
            case Operation::FSH:
            case Operation::FMADD_H:
            case Operation::FMSUB_H:
            case Operation::FNMADD_H:
            case Operation::FNMSUB_H:
            case Operation::FADD_H:
            case Operation::FSUB_H:
            case Operation::FMUL_H:
            case Operation::FDIV_H:
            case Operation::FSQRT_H:
            case Operation::FSGNJ_H:
            case Operation::FSGNJN_H:
            case Operation::FSGNJX_H:
            case Operation::FMIN_H:
            case Operation::FMAX_H:
            case Operation::FCVT_W_H:
            case Operation::FCVT_WU_H:
            case Operation::FMV_X_H:
            case Operation::FEQ_H:
            case Operation::FLT_H:
            case Operation::FLE_H:
            case Operation::FCLASS_H:
            case Operation::FCVT_H_W:
            case Operation::FCVT_H_WU:
            case Operation::FMV_H_X:
            case Operation::FCVT_S_H:
            case Operation::FCVT_H_S:
            case Operation::FCVT_H_D:
            case Operation::FCVT_D_H:
            // R64Zfh standard extension
            case Operation::FCVT_L_H:
            case Operation::FCVT_LU_H:
            case Operation::FCVT_H_L:
            case Operation::FCVT_H_LU:
            // RV32F standard extension
            case Operation::FLW:
            case Operation::FSW:
            case Operation::FMADD_S:
            case Operation::FMSUB_S:
            case Operation::FNMADD_S:
            case Operation::FNMSUB_S:
            case Operation::FADD_S:
            case Operation::FSUB_S:
            case Operation::FMUL_S:
            case Operation::FDIV_S:
            case Operation::FSQRT_S:
            case Operation::FSGNJ_S:
            case Operation::FSGNJN_S:
            case Operation::FSGNJX_S:
            case Operation::FMIN_S:
            case Operation::FMAX_S:
            case Operation::FCVT_W_S:
            case Operation::FCVT_WU_S:
            case Operation::FMV_X_W:
            case Operation::FEQ_S:
            case Operation::FLT_S:
            case Operation::FLE_S:
            case Operation::FCLASS_S:
            case Operation::FCVT_S_W:
            case Operation::FCVT_S_WU:
            case Operation::FMV_W_X:
            // RV64F standard extension (addition to RV32F)
            case Operation::FCVT_L_S:
            case Operation::FCVT_LU_S:
            case Operation::FCVT_S_L:
            case Operation::FCVT_S_LU:
            // RV32D standard extension
            case Operation::FLD:
            case Operation::FSD:
            case Operation::FMADD_D:
            case Operation::FMSUB_D:
            case Operation::FNMSUB_D:
            case Operation::FNMADD_D:
            case Operation::FADD_D:
            case Operation::FSUB_D:
            case Operation::FMUL_D:
            case Operation::FDIV_D:
            case Operation::FSQRT_D:
            case Operation::FSGNJ_D:
            case Operation::FSGNJN_D:
            case Operation::FSGNJX_D:
            case Operation::FMIN_D:
            case Operation::FMAX_D:
            case Operation::FCVT_S_D:
            case Operation::FCVT_D_S:
            case Operation::FEQ_D:
            case Operation::FLT_D:
            case Operation::FLE_D:
            case Operation::FCLASS_D:
            case Operation::FCVT_W_D:
            case Operation::FCVT_WU_D:
            case Operation::FCVT_D_W:
            case Operation::FCVT_D_WU:
            // RV64D standard extension (addition to RV32D)
            case Operation::FCVT_L_D:
            case Operation::FCVT_LU_D:
            case Operation::FMV_X_D:
            case Operation::FCVT_D_L:
            case Operation::FCVT_D_LU:
            case Operation::FMV_D_X:
                return true;
            default:
                return false;
        }
    }
}