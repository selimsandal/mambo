#ifndef EXAMPLES_HOTSPOT_HELPERS_H
#define EXAMPLES_HOTSPOT_HELPERS_H

#include <stdint.h>

#if defined(__GNUC__)
#define HOTSPOT_NOINLINE __attribute__((noinline, noclone, noipa))
#else
#define HOTSPOT_NOINLINE __attribute__((noinline))
#endif

/*
  Marker helpers for demo workloads.

  These do not perform analysis themselves. They simply provide named symbols
  that make it easy to bracket the interesting region in a C workload while the
  dependency checker plugin performs the actual hotspot analysis.
*/
static HOTSPOT_NOINLINE void hotspot_start(void) {
  asm volatile("" ::: "memory");
}

static HOTSPOT_NOINLINE void hotspot_end(uint64_t sink) {
  asm volatile("" : : "r"(sink) : "memory");
}

#endif
