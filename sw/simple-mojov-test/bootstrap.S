.option norvc

/* Trap handler: loop forever (verhindert "null trap handler") */
.section .text, "ax"
.align 2
.globl trap_handler
trap_handler:
  j trap_handler

/* Reset/entry */
.section .text.start, "ax"
.align 2
.globl _start
_start:
  /* Stack */
  la   sp, _stack_top

  /* enable FP */
  li   t0, 0x00006000       # mask for FS field (bits 13:12)
  csrr t1, mstatus
  or   t1, t1, t0           # set FS = 11 (Dirty)
  csrw mstatus, t1

  /* mtvec setzen -> nie null trap handler */
  la   t0, trap_handler
  csrw mtvec, t0

  /* BSS nullen (für globale Variablen / uint128 buffers) */
  la   t0, _bss_start
  la   t1, _bss_end
1:
  bgeu t0, t1, 2f
  sd   zero, 0(t0)
  addi t0, t0, 8
  j    1b
2:
  /* main() */
      call main
  li a0, 0      /* exit code */
  li a7, 93     /* SYS_exit */
  ecall
1: j 1b

  /* wenn main zurückkommt: halt */
3:
  wfi
  j 3b