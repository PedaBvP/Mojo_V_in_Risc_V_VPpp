# Deine Quellen/Objekte
OBJECTS = bootstrap.o


# Optional: zusätzliche Files (z.B. syscall stubs) hier ergänzen
# OBJECTS += syscalls.o

# ISA/ABI Flags – anpassen falls euer Projekt andere nutzt
CFLAGS   = -march=rv64gc -mabi=lp64d
LDFLAGS += -Wl,-e,_start -Wl,--defsym,_stack_top=0x80020000 -nostartfiles

# Optional: wenn ihr newlib-nano/nosys braucht (nur falls Link-Errors wegen _write/_sbrk etc.)
# LDFLAGS += --specs=nano.specs --specs=nosys.specs

# VP++ Settings (kannst du überschreiben)
# VP ?= riscv64-vp
# VP_FLAGS ?= --intercept-syscalls --error-on-zero-traphandler=true

# Wichtig: Pfad anpassen! (je nachdem wo makefile.common liegt)
RISCV_PREFIX ?= riscv64-unknown-elf-
VP ?= riscv64-vp


include ../Makefile.common
