    .option norvc
    .section .text.start, "ax"
    .globl _start
    .align 2

/* --- Mojo-V CSR addresses (von dir) --- */
    .equ MOJOV_CFG,     0x0A0
    .equ MOJOV_CIPHERS, 0x0A1
    .equ MOJOV_KEYCFG,  0x0A3

/* --- TODO: Diese Bits musst du an DEINE Implementierung anpassen --- */
    .equ CFG_ENABLE_BIT,        (1 << 0)   /* Mojo-V global enable */
    .equ CFG_DATA_CONTRACT_BIT, (1 << 1)   /* data-contract enable (Beispiel) */

    .equ KEYCFG_KEY_VALID_BIT,  (1 << 0)   /* key valid (Beispiel) */

_start:
    /* Stack setzen (muss in deinem RAM liegen!) */
    li   sp, 0x00010000

    /* mtvec setzen -> minimaler Trap handler */
    la   t0, trap_entry
    csrw mtvec, t0

    /* ------------------------------------------------------------
       1) Mojo-V konfigurieren
       ------------------------------------------------------------ */


    li t2, 0x7620562D6F6A6F4D
    li t3, 0x31303023202E7265

    csrw MOJOV_KEYCFG, t2
    csrw MOJOV_KEYCFG, t3
    csrw MOJOV_KEYCFG, t4
    csrw MOJOV_KEYCFG, t4
    csrw MOJOV_KEYCFG, t4
    csrw MOJOV_KEYCFG, t4
    csrw MOJOV_KEYCFG, 0x3
    csrw MOJOV_KEYCFG, 0x0
       
    

    /* CFG: enable + data contract */
    li   t1, (CFG_ENABLE_BIT | CFG_DATA_CONTRACT_BIT)
    csrw MOJOV_CFG, t1


    /* KEYCFG: key valid setzen (damit SDE erlaubt ist) */

    /* ------------------------------------------------------------
       2) SDE ausführen (soll jetzt NICHT mehr trapen)
       ------------------------------------------------------------ */
    # sichere Adresse: Stack
    addi a7, sp, -16
    li   s10, 0x11223344

    # optional sanity: normal store (soll NICHT faulten)
    //sd   s10, 0(a7)

    addi s10, s10, 0x1

    # Mojo-V SDE test
    .insn s 0x0B, 1, s10, 0(a7)

    /* PASS: Wenn wir hier ankommen, wurde SDE NICHT geblockt */
    li   a0, 0
    li   a7, 93
    ecall

/* ------------------------------------------------------------
   Trap handler: exit(mcause & 0xff)
   -> dann siehst du im make: Error XX welchen mcause du hattest
   ------------------------------------------------------------ */
    .section .text.trap, "ax"
    .globl trap_entry
    .align 2
trap_entry:
    csrr a0, mcause
    andi a0, a0, 0xff
    li   a7, 93
    ecall
1:  j 1b
