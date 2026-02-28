#pragma once
#include <stdint.h>


typedef unsigned __int128 uint128_t;

 void putchar_sys(char c);

 void print_dec64(uint64_t v);

 void print_hex64(uint64_t v) ;

void dump_u64( uint64_t p);

 void print_str(const char *s);

 uint64_t cheap_unsalt_u128(const volatile uint128_t *ct);

 void print_label_dec(const char *label, uint64_t v);
 void print_label_hex(const char *label, const volatile uint128_t *v);