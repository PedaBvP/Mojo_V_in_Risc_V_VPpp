#include "util.h"

 void putchar_sys(char c) {
    register long a0 asm("a0") = 1;           // fd=stdout
    register long a1 asm("a1") = (long)&c;    // buf pointer!
    register long a2 asm("a2") = 1;           // len
    register long a7 asm("a7") = 64;          // SYS_write
    asm volatile ("ecall"
                  : "+r"(a0)
                  : "r"(a1), "r"(a2), "r"(a7)
                  : "memory");
}

 void print_dec64(uint64_t v) {
    char buf[32];
    int n = 0;

    if (v == 0) {
        putchar_sys('0');   // oder dein putchar()
        return;
    }

    while (v > 0) {
        uint64_t q = v / 10;
        uint64_t r = v - q * 10;
        buf[n++] = (char)('0' + r);
        v = q;
    }

    while (n--) putchar_sys(buf[n]);
}


 void print_hex64(uint64_t v) {
    const char *hex = "0123456789abcdef";
    for(int i=60;i>=0;i-=4)
        putchar_sys(hex[(v>>i)&0xF]);
}

void dump_u64( uint64_t p) {
    print_dec64(p);
    putchar_sys('\n');
}

 void print_str(const char *s)
{
    while (*s)
        putchar_sys(*s++);
}


 uint64_t cheap_unsalt_u128(const volatile uint128_t *ct)
{
    const volatile uint64_t *w = (const volatile uint64_t*)ct; // w[0]=lo, w[1]=hi
    return w[0] ^ 0x123456ULL;
}

 void print_label_dec(const char *label, uint64_t v) {
    print_str(label);
    print_dec64(v);
    putchar_sys('\n');
}

 void print_label_hex(const char *label, const volatile uint128_t *v) {
    uint64_t unsalted = cheap_unsalt_u128(v);
    print_str(label);
    print_dec64(unsalted);
    putchar_sys('\n');
}