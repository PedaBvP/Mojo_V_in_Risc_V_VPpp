# Implementation of Mojo V in RISC-V VP++

## Project Overview

This project implements the **Mojo V security extension** into the **RISC-V VP++ Virtual Prototype**.
The goal is to extend the existing virtual prototype with Mojo V specific security features, like custom instructions, CSR extensions, validation logic, and execution-time enforcement mechanisms.

The implementation integrates directly into the VP++ ISS infrastructure while maintaining functionality of the existing RISC-V simulation flow.

---

## Base Repository

This project is based on the official **RISC-V VP++** repository.

🔗 [**RISC-V VP++ Main Repository**](https://github.com/ics-jku/riscv-vp-plusplus)

For the following topics, please refer to the original VP++ repository:

* Build instructions
* Toolchain configuration
* Simulation execution
* Project structure
* SystemC integration

Most of the build process is identical to the standard RISC-V VP++ repository and follows its documented instructions.

However, minimal adjustments are required for the GNU RISC-V toolchain configuration.

Since this project uses additional ISA extensions (e.g., rv64, Zicond) and custom instruction encodings.

```
# in some source folder
git clone https://github.com/riscv/riscv-gnu-toolchain.git
cd riscv-gnu-toolchain
git submodule update --init --recursive # this may take a while.
/configure --prefix=$(pwd)/../riscv-gnu-toolchain-dist-rv64gc-lp64 --with-arch=rv64gc --with-abi=lp64
make -j"$(nproc)"
```
---

## Mojo V Implementation Repository

The Mojo V specific implementation can be found here:

🔗 [**Mojo V Implementation Repository**](https://github.com/toddmaustin/mojo-v?tab=readme-ov-file)

This repository contains all extension-specific changes and additions.



## Implemented Features

### 1. Custom Instructions

The following Mojo V specific instructions were implemented using GNU assembler `.insn` encoding:

* `LDE`
* `SDE`
* `FLDE`
* `FSDE`

Characteristics:

* Custom opcode: `0x0B`
* Custom funct3 encodings
* Integrated into:

  * Instruction decoding
  * ISS execution stage
  * Load/Store cache handling


### 2. ISS Integration

Mojo V logic was integrated into:

* Instruction execution stage (ISS)
* Opcode handling
* Data-flow hash calculation
* Security enforcement logic

Special handling includes:

* Descriptor generation (mask + encoding)
* 64-bit opcode descriptor construction
* Hash-based validation mechanisms



### 3. Mojo V Rule Set Implementation & Validation

The complete Mojo V rule set has been implemented and integrated into the VP++ execution flow.

The validation happens at decode time and ensures that no data gets leaked.



### 4. Opcode Descriptor & Proof-Carrying Inspired Concept

The implementation fully supports all Mojo V modes and the existing instruction mask and encoding structure of VP++.

Currently, descriptor validation operates using pseudo-hash values, ensuring correct architectural integration and validation behavior.

---

## Current Status

The project is currently in the stage of:

### Integration of Official Mojo V Tests

The official test suite is being connected to the VP++ simulation environment.

This includes verification of:

* Instruction behavior
* CSR correctness
* Load/store correctness
* Security validation logic


Local Tests have been added to show the functionality of the Project

in sw
```
cd simple-mojov-test          # can be replaced with different example
make TEST=BUBBLE              # (requires RISC-V GNU toolchain in PATH)
make TEST=BUBBLE sim          # (requires *riscv64-vp*, i.e. *vp/build/bin/riscv64-vp*, executable in PATH)
```
or
```
cd simple-mojov-test          # can be replaced with different example
make TEST=SIMPLEMAX              # (requires RISC-V GNU toolchain in PATH)
make TEST=SIMPLEMAX sim          # (requires *riscv64-vp*, i.e. *vp/build/bin/riscv64-vp*, executable in PATH)
```
---

## Planned Work

### Negative Testing

The next planned step is:

* Testing invalid instruction scenarios
* Testing incorrect CSR configurations
* Testing security violations
* Verifying correct exception behavior
* Ensuring Mojo V security rules cannot be bypassed

This will further increase robustness and correctness guarantees.
