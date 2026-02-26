#pragma once
#include "mojov.h"

	bool mojov_load_decrypt(
                uint64_t addr,
                uint64_t contract_sig_expected,
                MojovFormat fmt,
                uint64_t &out_val,
                bool fp );

	void mojov_store_encrypted(
                uint64_t addr,
                uint64_t plaintext_val,
                uint64_t contract_sig,
                MojovFormat fmt,
                bool fp);

    void install_contract();

	void calc_dfhash(Operation::OpId opId);

    void get_reg_values(Operation::Type type, uint64_t &rs1, uint64_t &rs2);
	
    void get_fpReg_values(Operation::Type type, uint64_t &rs1, uint64_t &rs2, uint64_t &rs3);
    
    uint64_t fpReg_value(uint32_t reg);
    
    uint64_t reg_value(uint32_t reg);
