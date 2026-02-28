OUTPUT_ARCH("riscv")
ENTRY(_start)

/* Für VP++ Reset-PC=0: Link an 0x0 */
MEMORY
{
  RAM (rwx) : ORIGIN = 0x00000000, LENGTH = 512K
}

SECTIONS
{
  . = ORIGIN(RAM);

  /* Start muss ganz vorne liegen */
  .text : ALIGN(4) {
    KEEP(*(.text.start))
    *(.text*)
    *(.rodata*)
    *(.srodata*)
  } > RAM

  .data : ALIGN(8) {
    _data_start = .;
    *(.data*)
    *(.sdata*)
    _data_end = .;
  } > RAM

  .bss : ALIGN(8) {
    _bss_start = .;
    *(.bss*)
    *(.sbss*)
    *(COMMON)
    _bss_end = .;
  } > RAM

  /* Stack am RAM-Ende */
  _stack_top = ORIGIN(RAM) + LENGTH(RAM);

  /* gp für kleine-data Relocs */
  __global_pointer$ = ORIGIN(RAM) + 0x800;
}