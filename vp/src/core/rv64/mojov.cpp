#include "mojov.h"
#include "iss.h"

namespace rv64{

    uint64_t mojov_keycfg_buf[8] = {0};
    uint8_t  mojov_keycfg_idx = 0;
    __uint128_t mojov_sym_key = 0;
    uint64_t mojov_contract_sig = 0;
    uint64_t mojov_salt = 0;
    uint64_t mojov_ciphers_active = 0;

    uint64_t ISS::key_lo(__uint128_t k) {
        return static_cast<uint64_t>(k);
    }

    uint64_t ISS::key_hi(__uint128_t k) {
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
    }

    void ISS::mojov_store_encrypted(
        uint64_t addr,
        uint64_t plaintext_val,
        uint64_t contract_sig,
        MojovFormat fmt,
        uint64_t metadata)
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
                                                        contract_sig, metadata);
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
        uint64_t &out_metadata )
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
                out_metadata = 0;
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
                out_metadata = meta;
                return true;
            }
        }
        return false;
    }


    AeadResultFast ISS::mojov_aead_encrypt_fast(
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

    bool ISS::mojov_aead_decrypt_fast(
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


    AeadResultStrong ISS::mojov_aead_encrypt_strong(
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

    bool ISS::mojov_aead_decrypt_strong(
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
}