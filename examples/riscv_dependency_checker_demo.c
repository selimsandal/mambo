/*
  C demo workload for plugins/dependency_checker.c.

  The code marks the interesting region with hotspot_start() and
  hotspot_end(). Inside that region it emits three LEJ patterns:
    load -> mul -> add
    load -> div -> add
    load -> rem -> add

  The per-chain and per-hotspot counts should match the loop trip count
  exactly. The global executed totals in stats.txt can be slightly higher
  because process startup and teardown code may also execute expensive
  instructions before and after main().
*/

#include <stdint.h>

#include "hotspot_helpers.h"

#ifndef __riscv
#error "This demo is intended for RISC-V."
#endif

static const uint64_t values[3] = {3, 9, 11};

uint64_t hotspot_mul_chain(const uint64_t *base, uint64_t seed);
uint64_t hotspot_div_chain(const uint64_t *base, uint64_t dividend,
                           uint64_t divisor);
uint64_t hotspot_rem_chain(const uint64_t *base, uint64_t dividend,
                           uint64_t divisor);

__asm__(
    ".text\n"
    ".align 2\n"
    ".globl hotspot_mul_chain\n"
    ".type hotspot_mul_chain, @function\n"
    "hotspot_mul_chain:\n"
    "  ld t0, 0(a0)\n"
    "  mul t1, a1, a1\n"
    "  add a0, t0, t1\n"
    "  ret\n"
    ".size hotspot_mul_chain, .-hotspot_mul_chain\n"
    ".align 2\n"
    ".globl hotspot_div_chain\n"
    ".type hotspot_div_chain, @function\n"
    "hotspot_div_chain:\n"
    "  ld t0, 8(a0)\n"
    "  div t1, a1, a2\n"
    "  add a0, t0, t1\n"
    "  ret\n"
    ".size hotspot_div_chain, .-hotspot_div_chain\n"
    ".align 2\n"
    ".globl hotspot_rem_chain\n"
    ".type hotspot_rem_chain, @function\n"
    "hotspot_rem_chain:\n"
    "  ld t0, 16(a0)\n"
    "  rem t1, a1, a2\n"
    "  add a0, t0, t1\n"
    "  ret\n"
    ".size hotspot_rem_chain, .-hotspot_rem_chain\n");

static HOTSPOT_NOINLINE uint64_t hotspot_region(const uint64_t *base,
                                                uint64_t iterations) {
  uint64_t acc = 0;
  uint64_t mul_seed = iterations;
  uint64_t dividend = 400000;
  const uint64_t divisor = 7;

  hotspot_start();

  for (uint64_t i = 0; i < iterations; i++) {
    acc += hotspot_mul_chain(base, mul_seed);
    acc += hotspot_div_chain(base, dividend, divisor);
    acc += hotspot_rem_chain(base, dividend, divisor);
    mul_seed--;
    dividend -= 13;
  }

  hotspot_end(acc);
  return acc;
}

int main(void) {
  volatile uint64_t sink = hotspot_region(values, 20000);

  return sink == 0;
}
