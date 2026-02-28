#include <stdint.h>
#include "common/util.h"

typedef unsigned __int128 uint128_t;

#define LDE(rd,base,ofs) ".insn i 0xb, 0x0, " #rd ", " #base ", " #ofs "\n\t"
#define SDE(src,base,ofs) ".insn s 0xb, 0x1, " #src ", " #ofs "(" #base ")\n\t"

#define CSR_MPRIVREGCFG 0x0a0

static inline void write_mprivregcfg(uint64_t value)
{
  __asm__ volatile ("csrw %0, %1" :: "i"(CSR_MPRIVREGCFG), "rK"(value));
}

/* ---------- dataset ---------- */
#define N 32
uint64_t raw_data[N];
uint128_t secret_data[N];
uint128_t swaps;

/* ---------- simple RNG (no libs) ---------- */
static uint64_t rng_state = 42;
static uint64_t xorshift64(void) {
  uint64_t x = rng_state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  rng_state = x;
  return x;
}

/* ---------- Bubble sort on secret_data (same idea as official) ---------- */
static void bubblesort(uint128_t *data, unsigned size)
{
  for (unsigned i = 0; i < size - 1; i++) {
    for (unsigned j = 0; j < size - 1; j++) {
      __asm__ volatile (
        /* load encrypted operands */
        LDE(  t3, %0, 0)           /* data[j]   */
        LDE(  t4, %1, 0)           /* data[j+1] */

        /* swap predicate: t5 = (t4 < t3) */
        "slt  t5, t4, t3\n\t"

        /* data[j] = swap ? data[j+1] : data[j] */
        "czero.eqz t6, t4, t5\n\t" /* if swap==0 => 0 else t4 */
        "czero.nez t5, t3, t5\n\t" /* if swap!=0 => 0 else t3 (note: overwrites t5) */
        "or        t6, t5, t6\n\t"
        SDE(       t6, %0, 0)

        /* recompute swap predicate (because t5 got clobbered) */
        "slt  t5, t4, t3\n\t"

        /* data[j+1] = swap ? old data[j] : old data[j+1] */
        "czero.eqz t6, t3, t5\n\t"
        "czero.nez t3, t4, t5\n\t"
        "or        t6, t3, t6\n\t"
        SDE(       t6, %1, 0)

        /* swaps++ (optional, we just always add t5 (0/1) ) */
        LDE(  t3, %2, 0)
        "add  t4, t3, t5\n\t"
        SDE(  t4, %2, 0)

        :
        : "r"(&data[j]), "r"(&data[j+1]), "r"(&swaps)
        : "t3","t4","t5","t6","memory"
      );
    }
  }
}

/* ---------- printing helpers ---------- */
static void dump_ct_array(const char *title, volatile uint128_t *arr, unsigned n)
{
  print_str(title);
  putchar_sys('\n');
  for (unsigned i = 0; i < n; i++) {
    // print only low 64b in hex to keep it short
    volatile uint64_t *w = (volatile uint64_t*)&arr[i];
    print_str("  ct["); print_dec64(i); print_label_hex("] = ",&arr[i]);
  }
}

int main(void)
{
  write_mprivregcfg(1);

  /* init swaps=0 */
  __asm__ volatile (
    "mv t3, x0\n\t"
    SDE(t3, %0, 0)
    :
    : "r"(&swaps)
    : "t3","memory"
  );

  /* fill raw_data and encrypt into secret_data */
  for (unsigned i = 0; i < N; i++) {
    raw_data[i] = xorshift64() & 0x3ff; /* small numbers */
    __asm__ volatile (
      "ld  t3, (%0)\n\t"
      SDE(t3, %1, 0)
      :
      : "r"(&raw_data[i]), "r"(&secret_data[i])
      : "t3","memory"
    );
  }

  print_str("Before sort (ciphertext low-words):\n");
  dump_ct_array("secret_data", secret_data, N);

  bubblesort(secret_data, N);

  print_str("After sort (ciphertext low-words):\n");
  dump_ct_array("secret_data", secret_data, N);

  /* show swap counter ciphertext (low 64) */
  {
    volatile uint64_t *w = (volatile uint64_t*)&swaps;
    print_str("swaps ct lo=0x"); print_hex64(w[0]); putchar_sys('\n');
  }

  write_mprivregcfg(0);
  return 0;
}