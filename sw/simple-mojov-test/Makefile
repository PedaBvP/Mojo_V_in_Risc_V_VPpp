# Toolchain
RISCV_PREFIX ?= riscv64-unknown-elf-
VP ?= riscv64-vp
VP_FLAGS ?= --intercept-syscalls --error-on-zero-traphandler=true

# Output
EXECUTABLE ?= main

# Objekte (bootstrap + dein C)
TEST ?= simplemax
MAIN_SRC := main_$(TEST).c

OBJECTS = bootstrap.o main.o util.o

main.o: $(MAIN_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $(MAIN_SRC) -o $@

# ISA/ABI + nötig für czero.* (Zicond) + robustes Bare-Metal
CFLAGS  += -march=rv64gc_zicond -mabi=lp64d -O2 -mcmodel=medany \
           -ffreestanding -fno-builtin -nostdlib -nostartfiles
ASFLAGS += -march=rv64gc_zicond -mabi=lp64d -mcmodel=medany

# Linker: unser Script, keine CRT/startfiles
LDFLAGS += -T link.ld -Wl,-e,_start -nostdlib -nostartfiles

util.o: common/util.c common/util.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

include ../Makefile.common