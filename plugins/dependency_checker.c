/*
  LEJ dependency chain detector plugin for MAMBO.

  L: long-latency load instructions
  E: expensive arithmetic instructions (mul/div/rem/fmul/fdiv)
  J: join instructions that consume both dependency chains within a bounded
     instruction window
*/

#ifdef PLUGINS_NEW

#ifndef __riscv
#error "The dependency_checker plugin currently supports RISC-V only."
#endif

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../plugins.h"

#define WINDOW_SIZE 16
#define MAX_GAP 4
#define CHAIN_MAP_INIT 1024
#define HOTSPOT_TOP_LIMIT 20

typedef enum {
  INST_OTHER = 0,
  INST_LONG = 1,
  INST_EXPENSIVE = 2,
} inst_class_t;

typedef enum {
  EXPENSIVE_KIND_NONE = 0,
  EXPENSIVE_KIND_MUL = 1,
  EXPENSIVE_KIND_DIV = 2,
  EXPENSIVE_KIND_REM = 3,
  EXPENSIVE_KIND_FMUL = 4,
  EXPENSIVE_KIND_FDIV = 5,
  EXPENSIVE_KIND_COUNT = 6,
} expensive_kind_t;

typedef struct {
  inst_class_t iclass;
  expensive_kind_t expensive_kind;
  int dest_reg;
  int src_reg[2];
  uintptr_t pc;
  char text[80];
} inst_info_t;

typedef struct chain_entry chain_entry_t;
struct chain_entry {
  uint64_t count;
  uintptr_t long_addr;
  uintptr_t expensive_addr;
  uintptr_t join_addr;
  int dep_reg_l;
  int dep_reg_e;
  int chain_id;
  expensive_kind_t expensive_kind;
  char long_text[80];
  char expensive_text[80];
  char join_text[80];
  chain_entry_t *next;
};

typedef struct local_chain_counter local_chain_counter_t;
struct local_chain_counter {
  chain_entry_t *chain;
  uint64_t count;
  local_chain_counter_t *next;
};

typedef enum {
  HOTSPOT_ROLE_TOTAL = 0,
  HOTSPOT_ROLE_LONG = 1,
  HOTSPOT_ROLE_EXPENSIVE = 2,
  HOTSPOT_ROLE_JOIN = 3,
} hotspot_role_t;

typedef struct {
  uintptr_t pc;
  uint64_t total_count;
  uint64_t long_count;
  uint64_t expensive_count;
  uint64_t join_count;
  uint64_t expensive_kind_counts[EXPENSIVE_KIND_COUNT];
  const char *text;
} hotspot_entry_t;

typedef struct {
  chain_entry_t **chains;
  size_t chain_count;
  uint64_t total_occurrences;
  uint64_t chain_occurrences_by_kind[EXPENSIVE_KIND_COUNT];
  size_t unique_chains_by_kind[EXPENSIVE_KIND_COUNT];
  chain_entry_t *most_common_chain;
  hotspot_entry_t *hotspots;
  size_t hotspot_count;
  hotspot_entry_t **hotspots_by_total;
  hotspot_entry_t **hotspots_by_long;
  hotspot_entry_t **hotspots_by_expensive;
  hotspot_entry_t **hotspots_by_join;
} analysis_data_t;

typedef struct {
  uint64_t total_instr;
  uint64_t total_long;
  uint64_t total_expensive;
  uint64_t total_expensive_by_kind[EXPENSIVE_KIND_COUNT];
  inst_info_t window[WINDOW_SIZE];
  int window_count;
  mambo_ht_t *chain_map; // hash -> local_chain_counter_t* collision list
} thread_data_t;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static chain_entry_t *g_chain_list = NULL;
static int g_next_chain_id = 1;
static uint64_t g_total_instr = 0;
static uint64_t g_total_long = 0;
static uint64_t g_total_expensive = 0;
static uint64_t g_total_expensive_by_kind[EXPENSIVE_KIND_COUNT] = {0};

static const char *const rv_reg_abi[32] = {
  "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
  "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
  "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
  "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};

static const char *const rv_fp_reg_names[32] = {
  "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
  "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",
  "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
  "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31"
};

static int encode_gpr_dest(unsigned int reg) {
  return reg == 0 ? -1 : (int)reg;
}

static int encode_gpr_src(unsigned int reg) {
  return (int)reg;
}

static int encode_fpr(unsigned int reg) {
  return 32 + (int)reg;
}

static const char *reg_name(int reg) {
  if (reg >= 0 && reg < 32) {
    return rv_reg_abi[reg];
  }
  if (reg >= 32 && reg < 64) {
    return rv_fp_reg_names[reg - 32];
  }

  return "?";
}

static const char *expensive_kind_name(expensive_kind_t kind) {
  switch (kind) {
    case EXPENSIVE_KIND_MUL:
      return "mul";
    case EXPENSIVE_KIND_DIV:
      return "div";
    case EXPENSIVE_KIND_REM:
      return "rem";
    case EXPENSIVE_KIND_FMUL:
      return "fmul";
    case EXPENSIVE_KIND_FDIV:
      return "fdiv";
    case EXPENSIVE_KIND_NONE:
    case EXPENSIVE_KIND_COUNT:
      break;
  }

  return "none";
}

static const char *expensive_kind_summary_label(expensive_kind_t kind) {
  switch (kind) {
    case EXPENSIVE_KIND_MUL:
      return "Integer mul family";
    case EXPENSIVE_KIND_DIV:
      return "Integer div family";
    case EXPENSIVE_KIND_REM:
      return "Integer rem family";
    case EXPENSIVE_KIND_FMUL:
      return "FP mul family";
    case EXPENSIVE_KIND_FDIV:
      return "FP div family";
    case EXPENSIVE_KIND_NONE:
    case EXPENSIVE_KIND_COUNT:
      break;
  }

  return "Unknown family";
}

static void write_expensive_kind_breakdown(FILE *file, const uint64_t *counts,
                                           uint64_t total_count,
                                           const size_t *unique_counts) {
  for (int kind = EXPENSIVE_KIND_MUL; kind < EXPENSIVE_KIND_COUNT; kind++) {
    expensive_kind_t expensive_kind = (expensive_kind_t)kind;

    fprintf(file, "  %-25s: %" PRIu64,
            expensive_kind_summary_label(expensive_kind), counts[kind]);

    if (unique_counts != NULL) {
      fprintf(file, " occurrences across %zu unique chains",
              unique_counts[kind]);
    } else {
      fprintf(file, " executed");
    }

    if (total_count > 0) {
      fprintf(file, " (%.4f%%)",
              100.0 * (double)counts[kind] / (double)total_count);
    }

    fprintf(file, "\n");
  }
}

static void write_expensive_kind_counts(FILE *file, const uint64_t *counts) {
  fprintf(file, "mul/div/rem/fmul/fdiv = %" PRIu64 "/%" PRIu64 "/%" PRIu64
          "/%" PRIu64 "/%" PRIu64,
          counts[EXPENSIVE_KIND_MUL], counts[EXPENSIVE_KIND_DIV],
          counts[EXPENSIVE_KIND_REM], counts[EXPENSIVE_KIND_FMUL],
          counts[EXPENSIVE_KIND_FDIV]);
}

static uintptr_t hash_chain_key(uintptr_t long_addr, uintptr_t expensive_addr,
                                uintptr_t join_addr) {
  uintptr_t key = long_addr;

  key ^= expensive_addr + (key << 6) + (key >> 2);
  key ^= join_addr + (key << 6) + (key >> 2);

  return (key == 0) ? 1 : key;
}

static bool chain_matches(const chain_entry_t *entry, uintptr_t long_addr,
                          uintptr_t expensive_addr, uintptr_t join_addr) {
  return entry != NULL &&
         entry->long_addr == long_addr &&
         entry->expensive_addr == expensive_addr &&
         entry->join_addr == join_addr;
}

static chain_entry_t *find_global_chain(uintptr_t long_addr,
                                        uintptr_t expensive_addr,
                                        uintptr_t join_addr) {
  for (chain_entry_t *entry = g_chain_list; entry != NULL; entry = entry->next) {
    if (chain_matches(entry, long_addr, expensive_addr, join_addr)) {
      return entry;
    }
  }

  return NULL;
}

static int compare_chain_rank_desc(const void *lhs, const void *rhs) {
  const chain_entry_t *const *left = (const chain_entry_t *const *)lhs;
  const chain_entry_t *const *right = (const chain_entry_t *const *)rhs;

  if ((*left)->count < (*right)->count) {
    return 1;
  }
  if ((*left)->count > (*right)->count) {
    return -1;
  }
  if ((*left)->chain_id > (*right)->chain_id) {
    return 1;
  }
  if ((*left)->chain_id < (*right)->chain_id) {
    return -1;
  }

  return 0;
}

static uint64_t hotspot_role_count(const hotspot_entry_t *entry,
                                   hotspot_role_t role) {
  switch (role) {
    case HOTSPOT_ROLE_TOTAL:
      return entry->total_count;
    case HOTSPOT_ROLE_LONG:
      return entry->long_count;
    case HOTSPOT_ROLE_EXPENSIVE:
      return entry->expensive_count;
    case HOTSPOT_ROLE_JOIN:
      return entry->join_count;
  }

  return 0;
}

static int compare_hotspot_rank_desc(const hotspot_entry_t *left,
                                     const hotspot_entry_t *right,
                                     hotspot_role_t role) {
  uint64_t left_role_count = hotspot_role_count(left, role);
  uint64_t right_role_count = hotspot_role_count(right, role);

  if (left_role_count < right_role_count) {
    return 1;
  }
  if (left_role_count > right_role_count) {
    return -1;
  }
  if (left->total_count < right->total_count) {
    return 1;
  }
  if (left->total_count > right->total_count) {
    return -1;
  }
  if (left->pc > right->pc) {
    return 1;
  }
  if (left->pc < right->pc) {
    return -1;
  }

  return 0;
}

static int compare_hotspot_total_desc(const void *lhs, const void *rhs) {
  const hotspot_entry_t *const *left = (const hotspot_entry_t *const *)lhs;
  const hotspot_entry_t *const *right = (const hotspot_entry_t *const *)rhs;

  return compare_hotspot_rank_desc(*left, *right, HOTSPOT_ROLE_TOTAL);
}

static int compare_hotspot_long_desc(const void *lhs, const void *rhs) {
  const hotspot_entry_t *const *left = (const hotspot_entry_t *const *)lhs;
  const hotspot_entry_t *const *right = (const hotspot_entry_t *const *)rhs;

  return compare_hotspot_rank_desc(*left, *right, HOTSPOT_ROLE_LONG);
}

static int compare_hotspot_expensive_desc(const void *lhs, const void *rhs) {
  const hotspot_entry_t *const *left = (const hotspot_entry_t *const *)lhs;
  const hotspot_entry_t *const *right = (const hotspot_entry_t *const *)rhs;

  return compare_hotspot_rank_desc(*left, *right, HOTSPOT_ROLE_EXPENSIVE);
}

static int compare_hotspot_join_desc(const void *lhs, const void *rhs) {
  const hotspot_entry_t *const *left = (const hotspot_entry_t *const *)lhs;
  const hotspot_entry_t *const *right = (const hotspot_entry_t *const *)rhs;

  return compare_hotspot_rank_desc(*left, *right, HOTSPOT_ROLE_JOIN);
}

static hotspot_entry_t *lookup_or_create_hotspot(mambo_ht_t *hotspot_map,
                                                 hotspot_entry_t *hotspots,
                                                 size_t *hotspot_count,
                                                 uintptr_t pc,
                                                 const char *text) {
  uintptr_t index_plus_one = 0;

  assert(pc != 0);

  if (mambo_ht_get(hotspot_map, pc, &index_plus_one) == 0) {
    return &hotspots[index_plus_one - 1];
  }

  hotspot_entry_t *entry = &hotspots[*hotspot_count];

  memset(entry, 0, sizeof(*entry));
  entry->pc = pc;
  entry->text = text;

  (*hotspot_count)++;
  assert(mambo_ht_add(hotspot_map, pc, (uintptr_t)(*hotspot_count)) == 0);

  return entry;
}

static void add_hotspot_count(mambo_ht_t *hotspot_map, hotspot_entry_t *hotspots,
                              size_t *hotspot_count, uintptr_t pc,
                              const char *text, hotspot_role_t role,
                              expensive_kind_t expensive_kind,
                              uint64_t count) {
  hotspot_entry_t *entry =
      lookup_or_create_hotspot(hotspot_map, hotspots, hotspot_count, pc, text);

  entry->total_count += count;
  if (expensive_kind > EXPENSIVE_KIND_NONE &&
      expensive_kind < EXPENSIVE_KIND_COUNT) {
    entry->expensive_kind_counts[expensive_kind] += count;
  }

  switch (role) {
    case HOTSPOT_ROLE_TOTAL:
      break;
    case HOTSPOT_ROLE_LONG:
      entry->long_count += count;
      break;
    case HOTSPOT_ROLE_EXPENSIVE:
      entry->expensive_count += count;
      break;
    case HOTSPOT_ROLE_JOIN:
      entry->join_count += count;
      break;
  }
}

static void free_analysis_data(analysis_data_t *analysis) {
  free(analysis->chains);
  free(analysis->hotspots);
  free(analysis->hotspots_by_total);
  free(analysis->hotspots_by_long);
  free(analysis->hotspots_by_expensive);
  free(analysis->hotspots_by_join);

  memset(analysis, 0, sizeof(*analysis));
}

static void prepare_analysis_data(analysis_data_t *analysis) {
  mambo_ht_t hotspot_map;
  size_t chain_index = 0;

  memset(analysis, 0, sizeof(*analysis));

  for (chain_entry_t *entry = g_chain_list; entry != NULL; entry = entry->next) {
    analysis->chain_count++;
    analysis->total_occurrences += entry->count;

    if (analysis->most_common_chain == NULL ||
        entry->count > analysis->most_common_chain->count) {
      analysis->most_common_chain = entry;
    }
  }

  if (analysis->chain_count == 0) {
    return;
  }

  analysis->chains = calloc(analysis->chain_count, sizeof(*analysis->chains));
  analysis->hotspots =
      calloc(analysis->chain_count * 3, sizeof(*analysis->hotspots));
  assert(analysis->chains != NULL);
  assert(analysis->hotspots != NULL);
  assert(mambo_ht_init(&hotspot_map, analysis->chain_count * 4, 0, 80, true) == 0);

  for (chain_entry_t *entry = g_chain_list; entry != NULL; entry = entry->next) {
    analysis->chains[chain_index++] = entry;
    if (entry->expensive_kind > EXPENSIVE_KIND_NONE &&
        entry->expensive_kind < EXPENSIVE_KIND_COUNT) {
      analysis->chain_occurrences_by_kind[entry->expensive_kind] += entry->count;
      analysis->unique_chains_by_kind[entry->expensive_kind]++;
    }

    add_hotspot_count(&hotspot_map, analysis->hotspots, &analysis->hotspot_count,
                      entry->long_addr, entry->long_text, HOTSPOT_ROLE_LONG,
                      entry->expensive_kind,
                      entry->count);
    add_hotspot_count(&hotspot_map, analysis->hotspots, &analysis->hotspot_count,
                      entry->expensive_addr, entry->expensive_text,
                      HOTSPOT_ROLE_EXPENSIVE, entry->expensive_kind,
                      entry->count);
    add_hotspot_count(&hotspot_map, analysis->hotspots, &analysis->hotspot_count,
                      entry->join_addr, entry->join_text, HOTSPOT_ROLE_JOIN,
                      entry->expensive_kind,
                      entry->count);
  }

  qsort(analysis->chains, analysis->chain_count, sizeof(*analysis->chains),
        compare_chain_rank_desc);

  analysis->hotspots_by_total =
      calloc(analysis->hotspot_count, sizeof(*analysis->hotspots_by_total));
  analysis->hotspots_by_long =
      calloc(analysis->hotspot_count, sizeof(*analysis->hotspots_by_long));
  analysis->hotspots_by_expensive =
      calloc(analysis->hotspot_count, sizeof(*analysis->hotspots_by_expensive));
  analysis->hotspots_by_join =
      calloc(analysis->hotspot_count, sizeof(*analysis->hotspots_by_join));
  assert(analysis->hotspots_by_total != NULL);
  assert(analysis->hotspots_by_long != NULL);
  assert(analysis->hotspots_by_expensive != NULL);
  assert(analysis->hotspots_by_join != NULL);

  for (size_t index = 0; index < analysis->hotspot_count; index++) {
    analysis->hotspots_by_total[index] = &analysis->hotspots[index];
    analysis->hotspots_by_long[index] = &analysis->hotspots[index];
    analysis->hotspots_by_expensive[index] = &analysis->hotspots[index];
    analysis->hotspots_by_join[index] = &analysis->hotspots[index];
  }

  qsort(analysis->hotspots_by_total, analysis->hotspot_count,
        sizeof(*analysis->hotspots_by_total), compare_hotspot_total_desc);
  qsort(analysis->hotspots_by_long, analysis->hotspot_count,
        sizeof(*analysis->hotspots_by_long), compare_hotspot_long_desc);
  qsort(analysis->hotspots_by_expensive, analysis->hotspot_count,
        sizeof(*analysis->hotspots_by_expensive), compare_hotspot_expensive_desc);
  qsort(analysis->hotspots_by_join, analysis->hotspot_count,
        sizeof(*analysis->hotspots_by_join), compare_hotspot_join_desc);

  free(hotspot_map.entries);
  pthread_mutex_destroy(&hotspot_map.lock);
}

static void write_hotspot_summary(FILE *stats_file, const char *label,
                                  hotspot_entry_t *const *ordered_hotspots,
                                  size_t hotspot_count, hotspot_role_t role,
                                  uint64_t total_occurrences) {
  if (hotspot_count == 0 ||
      hotspot_role_count(ordered_hotspots[0], role) == 0) {
    fprintf(stats_file, "  %-26s: (none detected)\n", label);
    return;
  }

  const hotspot_entry_t *entry = ordered_hotspots[0];
  uint64_t count = hotspot_role_count(entry, role);

  fprintf(stats_file, "  %-26s: 0x%" PRIxPTR " | %" PRIu64
          " occurrences (%.4f%%) | %s\n",
          label, entry->pc, count,
          total_occurrences > 0
              ? (100.0 * (double)count / (double)total_occurrences)
              : 0.0,
          entry->text != NULL ? entry->text : "(unknown)");
}

static void write_hotspot_section(FILE *hotspots_file, const char *title,
                                  hotspot_entry_t *const *ordered_hotspots,
                                  size_t hotspot_count, hotspot_role_t role,
                                  uint64_t total_occurrences) {
  size_t printed = 0;

  fprintf(hotspots_file, "%s\n", title);

  for (size_t index = 0;
       index < hotspot_count && printed < HOTSPOT_TOP_LIMIT;
       index++) {
    const hotspot_entry_t *entry = ordered_hotspots[index];
    uint64_t count = hotspot_role_count(entry, role);
    char *sym_name = NULL;
    char *filename = NULL;

    if (count == 0) {
      break;
    }

    get_symbol_info_by_addr(entry->pc, &sym_name, NULL, &filename);

    fprintf(hotspots_file,
            "  %2zu. %" PRIu64 " occurrences (%.4f%%) | roles L/E/J = "
            "%" PRIu64 "/%" PRIu64 "/%" PRIu64 "\n",
            printed + 1, count,
            total_occurrences > 0
                ? (100.0 * (double)count / (double)total_occurrences)
                : 0.0,
            entry->long_count, entry->expensive_count, entry->join_count);
    fprintf(hotspots_file, "      expensive kinds ");
    write_expensive_kind_counts(hotspots_file, entry->expensive_kind_counts);
    fprintf(hotspots_file, "\n");
    fprintf(hotspots_file, "      0x%016" PRIxPTR "  %-36s  [%s | %s]\n",
            entry->pc,
            entry->text != NULL ? entry->text : "(unknown)",
            sym_name != NULL ? sym_name : "(none)",
            filename != NULL ? filename : "(unknown)");

    free(sym_name);
    free(filename);
    printed++;
  }

  if (printed == 0) {
    fprintf(hotspots_file, "  (none detected)\n");
  }

  fprintf(hotspots_file, "\n");
}

static void decode_compressed_load_info(int inst, void *read_address,
                                        inst_info_t *info) {
  unsigned int rd_f;
  unsigned int rs1_f;
  unsigned int uimmhi;
  unsigned int uimmlo;
  const char *mnemonic = "c.load";

  info->iclass = INST_LONG;

  switch (inst) {
    case RISCV_C_LW:
      riscv_c_lw_decode_fields(read_address, &rd_f, &rs1_f, &uimmhi, &uimmlo);
      mnemonic = "c.lw";
      info->dest_reg = encode_gpr_dest(rd_f);
      info->src_reg[0] = encode_gpr_src(rs1_f);
      break;
    case RISCV_C_LD:
      riscv_c_ld_decode_fields(read_address, &rd_f, &rs1_f, &uimmhi, &uimmlo);
      mnemonic = "c.ld";
      info->dest_reg = encode_gpr_dest(rd_f);
      info->src_reg[0] = encode_gpr_src(rs1_f);
      break;
    case RISCV_C_FLD:
      riscv_c_fld_decode_fields(read_address, &rd_f, &rs1_f, &uimmhi, &uimmlo);
      mnemonic = "c.fld";
      info->dest_reg = encode_fpr(rd_f);
      info->src_reg[0] = encode_gpr_src(rs1_f);
      break;
    case RISCV_C_LWSP:
      riscv_c_lwsp_decode_fields(read_address, &rd_f, &uimmhi, &uimmlo);
      mnemonic = "c.lwsp";
      info->dest_reg = encode_gpr_dest(rd_f);
      info->src_reg[0] = encode_gpr_src(2);
      break;
    case RISCV_C_LDSP:
      riscv_c_ldsp_decode_fields(read_address, &rd_f, &uimmhi, &uimmlo);
      mnemonic = "c.ldsp";
      info->dest_reg = encode_gpr_dest(rd_f);
      info->src_reg[0] = encode_gpr_src(2);
      break;
    case RISCV_C_FLWSP:
      riscv_c_flwsp_decode_fields(read_address, &rd_f, &uimmhi, &uimmlo);
      mnemonic = "c.flwsp";
      info->dest_reg = encode_fpr(rd_f);
      info->src_reg[0] = encode_gpr_src(2);
      break;
    case RISCV_C_FLDSP:
      riscv_c_fldsp_decode_fields(read_address, &rd_f, &uimmhi, &uimmlo);
      mnemonic = "c.fldsp";
      info->dest_reg = encode_fpr(rd_f);
      info->src_reg[0] = encode_gpr_src(2);
      break;
    default:
      return;
  }

  snprintf(info->text, sizeof(info->text), "%s %s, (%s)",
           mnemonic, reg_name(info->dest_reg), reg_name(info->src_reg[0]));
}

static void decode_inst_info(mambo_context *ctx, inst_info_t *info) {
  int inst = mambo_get_inst(ctx);
  unsigned int rd_f;
  unsigned int rs1_f;
  unsigned int rs2_f;
  unsigned int imm_f;

  info->iclass = INST_OTHER;
  info->expensive_kind = EXPENSIVE_KIND_NONE;
  info->dest_reg = -1;
  info->src_reg[0] = -1;
  info->src_reg[1] = -1;
  info->pc = (uintptr_t)mambo_get_source_addr(ctx);
  info->text[0] = '\0';

  switch (inst) {
    case RISCV_LB:
    case RISCV_LH:
    case RISCV_LW:
    case RISCV_LBU:
    case RISCV_LHU:
    case RISCV_LWU:
    case RISCV_LD: {
      riscv_lw_decode_fields((uint16_t *)ctx->code.read_address,
                             &rd_f, &rs1_f, &imm_f);
      info->iclass = INST_LONG;
      info->dest_reg = encode_gpr_dest(rd_f);
      info->src_reg[0] = encode_gpr_src(rs1_f);

      const char *mnemonic =
        (inst == RISCV_LB) ? "lb" :
        (inst == RISCV_LH) ? "lh" :
        (inst == RISCV_LW) ? "lw" :
        (inst == RISCV_LBU) ? "lbu" :
        (inst == RISCV_LHU) ? "lhu" :
        (inst == RISCV_LWU) ? "lwu" : "ld";

      snprintf(info->text, sizeof(info->text), "%s %s, %d(%s)",
               mnemonic, reg_name(info->dest_reg), (int)imm_f,
               reg_name(info->src_reg[0]));
      break;
    }
    case RISCV_FLW:
    case RISCV_FLD: {
      riscv_lw_decode_fields((uint16_t *)ctx->code.read_address,
                             &rd_f, &rs1_f, &imm_f);
      info->iclass = INST_LONG;
      info->dest_reg = encode_fpr(rd_f);
      info->src_reg[0] = encode_gpr_src(rs1_f);

      snprintf(info->text, sizeof(info->text), "%s %s, %d(%s)",
               inst == RISCV_FLW ? "flw" : "fld",
               reg_name(info->dest_reg), (int)imm_f,
               reg_name(info->src_reg[0]));
      break;
    }
    case RISCV_C_FLD:
    case RISCV_C_LW:
    case RISCV_C_LD:
    case RISCV_C_FLDSP:
    case RISCV_C_LWSP:
    case RISCV_C_FLWSP:
    case RISCV_C_LDSP:
      decode_compressed_load_info(inst, (uint16_t *)ctx->code.read_address, info);
      break;
    case RISCV_MUL:
    case RISCV_MULH:
    case RISCV_MULHSU:
    case RISCV_MULHU:
    case RISCV_DIV:
    case RISCV_DIVU:
    case RISCV_REM:
    case RISCV_REMU:
    case RISCV_MULW:
    case RISCV_DIVW:
    case RISCV_DIVUW:
    case RISCV_REMW:
    case RISCV_REMUW: {
      expensive_kind_t expensive_kind = EXPENSIVE_KIND_MUL;
      riscv_add_decode_fields((uint16_t *)ctx->code.read_address,
                              &rd_f, &rs1_f, &rs2_f);
      info->iclass = INST_EXPENSIVE;
      info->expensive_kind = EXPENSIVE_KIND_MUL;
      info->dest_reg = encode_gpr_dest(rd_f);
      info->src_reg[0] = encode_gpr_src(rs1_f);
      info->src_reg[1] = encode_gpr_src(rs2_f);

      const char *mnemonic =
        (inst == RISCV_MUL) ? "mul" :
        (inst == RISCV_MULH) ? "mulh" :
        (inst == RISCV_MULHSU) ? "mulhsu" :
        (inst == RISCV_MULHU) ? "mulhu" :
        (inst == RISCV_DIV) ? (expensive_kind = EXPENSIVE_KIND_DIV, "div") :
        (inst == RISCV_DIVU) ? (expensive_kind = EXPENSIVE_KIND_DIV, "divu") :
        (inst == RISCV_REM) ? (expensive_kind = EXPENSIVE_KIND_REM, "rem") :
        (inst == RISCV_REMU) ? (expensive_kind = EXPENSIVE_KIND_REM, "remu") :
        (inst == RISCV_MULW) ? "mulw" :
        (inst == RISCV_DIVW) ? (expensive_kind = EXPENSIVE_KIND_DIV, "divw") :
        (inst == RISCV_DIVUW) ? (expensive_kind = EXPENSIVE_KIND_DIV, "divuw") :
        (inst == RISCV_REMW) ? (expensive_kind = EXPENSIVE_KIND_REM, "remw") :
        (expensive_kind = EXPENSIVE_KIND_REM, "remuw");

      info->expensive_kind = expensive_kind;

      snprintf(info->text, sizeof(info->text), "%s %s, %s, %s",
               mnemonic, reg_name(info->dest_reg), reg_name(info->src_reg[0]),
               reg_name(info->src_reg[1]));
      break;
    }
    case RISCV_FMUL_S:
    case RISCV_FDIV_S:
    case RISCV_FMUL_D:
    case RISCV_FDIV_D: {
      riscv_add_decode_fields((uint16_t *)ctx->code.read_address,
                              &rd_f, &rs1_f, &rs2_f);
      info->iclass = INST_EXPENSIVE;
      info->expensive_kind =
          (inst == RISCV_FDIV_S || inst == RISCV_FDIV_D)
              ? EXPENSIVE_KIND_FDIV
              : EXPENSIVE_KIND_FMUL;
      info->dest_reg = encode_fpr(rd_f);
      info->src_reg[0] = encode_fpr(rs1_f);
      info->src_reg[1] = encode_fpr(rs2_f);

      const char *mnemonic =
        (inst == RISCV_FMUL_S) ? "fmul.s" :
        (inst == RISCV_FDIV_S) ? "fdiv.s" :
        (inst == RISCV_FMUL_D) ? "fmul.d" : "fdiv.d";

      snprintf(info->text, sizeof(info->text), "%s %s, %s, %s",
               mnemonic, reg_name(info->dest_reg), reg_name(info->src_reg[0]),
               reg_name(info->src_reg[1]));
      break;
    }
    case RISCV_ADD:
    case RISCV_SUB:
    case RISCV_SLL:
    case RISCV_SLT:
    case RISCV_SLTU:
    case RISCV_XOR:
    case RISCV_SRL:
    case RISCV_SRA:
    case RISCV_OR:
    case RISCV_AND:
    case RISCV_ADDW:
    case RISCV_SUBW:
    case RISCV_SLLW:
    case RISCV_SRLW:
    case RISCV_SRAW: {
      riscv_add_decode_fields((uint16_t *)ctx->code.read_address,
                              &rd_f, &rs1_f, &rs2_f);
      info->dest_reg = encode_gpr_dest(rd_f);
      info->src_reg[0] = encode_gpr_src(rs1_f);
      info->src_reg[1] = encode_gpr_src(rs2_f);
      snprintf(info->text, sizeof(info->text), "r-op %s, %s, %s",
               reg_name(info->dest_reg), reg_name(info->src_reg[0]),
               reg_name(info->src_reg[1]));
      break;
    }
    case RISCV_FADD_S:
    case RISCV_FSUB_S:
    case RISCV_FMIN_S:
    case RISCV_FMAX_S:
    case RISCV_FSGNJ_S:
    case RISCV_FSGNJN_S:
    case RISCV_FSGNJX_S:
    case RISCV_FADD_D:
    case RISCV_FSUB_D:
    case RISCV_FMIN_D:
    case RISCV_FMAX_D:
    case RISCV_FSGNJ_D:
    case RISCV_FSGNJN_D:
    case RISCV_FSGNJX_D: {
      riscv_add_decode_fields((uint16_t *)ctx->code.read_address,
                              &rd_f, &rs1_f, &rs2_f);
      info->dest_reg = encode_fpr(rd_f);
      info->src_reg[0] = encode_fpr(rs1_f);
      info->src_reg[1] = encode_fpr(rs2_f);
      snprintf(info->text, sizeof(info->text), "r-op %s, %s, %s",
               reg_name(info->dest_reg), reg_name(info->src_reg[0]),
               reg_name(info->src_reg[1]));
      break;
    }
    default:
      snprintf(info->text, sizeof(info->text), "other@0x%" PRIxPTR, info->pc);
      break;
  }
}

static bool detect_lej(const inst_info_t *window, int window_count,
                       int l_idx, int e_idx, const inst_info_t *join_inst,
                       int *out_rd_l, int *out_rd_e) {
  const inst_info_t *long_inst = &window[l_idx];
  const inst_info_t *expensive_inst = &window[e_idx];
  int rd_l;
  int rd_e;
  bool join_reads_rdl;
  bool join_reads_rde;
  int first;
  int second;
  int first_rd;

  if (long_inst->iclass != INST_LONG || expensive_inst->iclass != INST_EXPENSIVE) {
    return false;
  }

  rd_l = long_inst->dest_reg;
  rd_e = expensive_inst->dest_reg;
  if (rd_l < 0 || rd_e < 0) {
    return false;
  }
  if (rd_l == rd_e || abs(l_idx - e_idx) > MAX_GAP) {
    return false;
  }

  join_reads_rdl = (join_inst->src_reg[0] == rd_l || join_inst->src_reg[1] == rd_l);
  join_reads_rde = (join_inst->src_reg[0] == rd_e || join_inst->src_reg[1] == rd_e);
  if (!join_reads_rdl || !join_reads_rde) {
    return false;
  }
  if (join_inst->src_reg[0] < 0 || join_inst->src_reg[1] < 0) {
    return false;
  }

  first = (l_idx < e_idx) ? l_idx : e_idx;
  second = (l_idx < e_idx) ? e_idx : l_idx;

  if (e_idx > l_idx &&
      (expensive_inst->src_reg[0] == rd_l || expensive_inst->src_reg[1] == rd_l)) {
    return false;
  }
  if (l_idx > e_idx && long_inst->src_reg[0] == rd_e) {
    return false;
  }

  first_rd = window[first].dest_reg;
  for (int index = first + 1; index < second; index++) {
    const inst_info_t *mid = &window[index];

    if (mid->dest_reg == rd_l || mid->dest_reg == rd_e) {
      return false;
    }
    if (first_rd >= 0 &&
        (mid->src_reg[0] == first_rd || mid->src_reg[1] == first_rd) &&
        mid->dest_reg >= 0 &&
        (window[second].src_reg[0] == mid->dest_reg ||
         window[second].src_reg[1] == mid->dest_reg)) {
      return false;
    }
  }

  for (int index = second + 1; index < window_count; index++) {
    if (window[index].dest_reg == rd_l || window[index].dest_reg == rd_e) {
      return false;
    }
  }

  *out_rd_l = rd_l;
  *out_rd_e = rd_e;
  return true;
}

static chain_entry_t *lookup_or_create_global_chain(mambo_context *ctx,
                                                    const inst_info_t *long_inst,
                                                    const inst_info_t *expensive_inst,
                                                    const inst_info_t *join_inst,
                                                    int rd_l, int rd_e) {
  chain_entry_t *entry;

  pthread_mutex_lock(&g_mutex);

  entry = find_global_chain(long_inst->pc, expensive_inst->pc, join_inst->pc);
  if (entry == NULL) {
    entry = (chain_entry_t *)mambo_alloc(ctx, sizeof(chain_entry_t));
    assert(entry != NULL);
    memset(entry, 0, sizeof(chain_entry_t));

    entry->long_addr = long_inst->pc;
    entry->expensive_addr = expensive_inst->pc;
    entry->join_addr = join_inst->pc;
    entry->dep_reg_l = rd_l;
    entry->dep_reg_e = rd_e;
    entry->chain_id = g_next_chain_id++;
    entry->expensive_kind = expensive_inst->expensive_kind;

    strncpy(entry->long_text, long_inst->text, sizeof(entry->long_text) - 1);
    strncpy(entry->expensive_text, expensive_inst->text,
            sizeof(entry->expensive_text) - 1);
    strncpy(entry->join_text, join_inst->text, sizeof(entry->join_text) - 1);

    entry->next = g_chain_list;
    g_chain_list = entry;

    fprintf(stderr,
            "[dep_chain] chain_%d allocated (L=0x%" PRIxPTR
            " E=0x%" PRIxPTR " J=0x%" PRIxPTR ")\n",
            entry->chain_id, entry->long_addr,
            entry->expensive_addr, entry->join_addr);
  }

  pthread_mutex_unlock(&g_mutex);

  return entry;
}

static local_chain_counter_t *lookup_or_create_local_chain_counter(
    mambo_context *ctx, thread_data_t *t_data, const inst_info_t *long_inst,
    const inst_info_t *expensive_inst, const inst_info_t *join_inst,
    int rd_l, int rd_e) {
  uintptr_t key = hash_chain_key(long_inst->pc, expensive_inst->pc, join_inst->pc);
  local_chain_counter_t *head = NULL;

  if (mambo_ht_get(t_data->chain_map, key, (uintptr_t *)&head) == 0) {
    for (local_chain_counter_t *entry = head; entry != NULL; entry = entry->next) {
      if (chain_matches(entry->chain, long_inst->pc, expensive_inst->pc, join_inst->pc)) {
        return entry;
      }
    }
  }

  local_chain_counter_t *local_counter =
      (local_chain_counter_t *)mambo_alloc(ctx, sizeof(local_chain_counter_t));
  assert(local_counter != NULL);
  memset(local_counter, 0, sizeof(local_chain_counter_t));

  local_counter->chain = lookup_or_create_global_chain(
      ctx, long_inst, expensive_inst, join_inst, rd_l, rd_e);
  local_counter->next = head;

  assert(mambo_ht_add(t_data->chain_map, key, (uintptr_t)local_counter) == 0);
  return local_counter;
}

static void write_stats(const analysis_data_t *analysis) {
  FILE *stats_file = fopen("stats.txt", "w");

  if (stats_file == NULL) {
    perror("[dep_chain] stats.txt");
    return;
  }

  fprintf(stats_file, "================================================\n");
  fprintf(stats_file, " LEJ Dependency Chain Detector -- Statistics\n");
  fprintf(stats_file, "================================================\n\n");
  fprintf(stats_file, "[Instruction Counts]\n");
  fprintf(stats_file, "  Total executed               : %" PRIu64 "\n", g_total_instr);
  fprintf(stats_file, "  Expensive (mul/div/rem/fmul/fdiv): %" PRIu64 "\n",
          g_total_expensive);
  fprintf(stats_file, "  Long      (load)             : %" PRIu64 "\n", g_total_long);

  if (g_total_instr > 0) {
    fprintf(stats_file, "  %% Expensive / Total : %.4f%%\n",
            100.0 * (double)g_total_expensive / (double)g_total_instr);
    fprintf(stats_file, "  %% Long      / Total : %.4f%%\n",
            100.0 * (double)g_total_long / (double)g_total_instr);
  }

  fprintf(stats_file, "\n[Expensive Instruction Breakdown]\n");
  write_expensive_kind_breakdown(stats_file, g_total_expensive_by_kind,
                                 g_total_expensive, NULL);

  fprintf(stats_file, "\n[Chain Statistics]\n");
  fprintf(stats_file, "  Total executed               : %" PRIu64 "\n", g_total_instr);
  fprintf(stats_file, "  LEJ chain occurrences (total): %" PRIu64 "\n",
          analysis->total_occurrences);
  fprintf(stats_file, "  Unique LEJ chains detected   : %zu\n",
          analysis->chain_count);

  if (g_total_instr > 0) {
    fprintf(stats_file, "  %% LEJ chains / Total : %.4f%%\n",
            100.0 * (double)analysis->total_occurrences / (double)g_total_instr);
  }

  if (analysis->most_common_chain != NULL) {
    fprintf(stats_file, "  Most occurred chain : chain_%d | %" PRIu64 " occurrences\n",
            analysis->most_common_chain->chain_id,
            analysis->most_common_chain->count);
  } else {
    fprintf(stats_file, "  Most occurred chain : (none detected)\n");
  }

  fprintf(stats_file, "\n[Chain Breakdown By Expensive Op]\n");
  write_expensive_kind_breakdown(stats_file, analysis->chain_occurrences_by_kind,
                                 analysis->total_occurrences,
                                 analysis->unique_chains_by_kind);

  fprintf(stats_file, "\n[Hotspot Summary]\n");
  write_hotspot_summary(stats_file, "Hottest instruction site",
                        analysis->hotspots_by_total, analysis->hotspot_count,
                        HOTSPOT_ROLE_TOTAL, analysis->total_occurrences);
  write_hotspot_summary(stats_file, "Hottest long producer",
                        analysis->hotspots_by_long, analysis->hotspot_count,
                        HOTSPOT_ROLE_LONG, analysis->total_occurrences);
  write_hotspot_summary(stats_file, "Hottest expensive op",
                        analysis->hotspots_by_expensive, analysis->hotspot_count,
                        HOTSPOT_ROLE_EXPENSIVE, analysis->total_occurrences);
  write_hotspot_summary(stats_file, "Hottest join consumer",
                        analysis->hotspots_by_join, analysis->hotspot_count,
                        HOTSPOT_ROLE_JOIN, analysis->total_occurrences);
  fprintf(stats_file, "  Detailed hotspot report      : hotspots.txt\n");

  fclose(stats_file);
  fprintf(stderr, "[dep_chain] stats.txt written.\n");
}

static void write_chains(const analysis_data_t *analysis) {
  FILE *chains_file = fopen("chains.txt", "w");

  if (chains_file == NULL) {
    perror("[dep_chain] chains.txt");
    return;
  }

  fprintf(chains_file, "================================================\n");
  fprintf(chains_file, " LEJ Dependency Chain Detector -- Chain Detail\n");
  fprintf(chains_file, "================================================\n\n");
  fprintf(chains_file, "[Chain Breakdown By Expensive Op]\n");
  write_expensive_kind_breakdown(chains_file, analysis->chain_occurrences_by_kind,
                                 analysis->total_occurrences,
                                 analysis->unique_chains_by_kind);
  fprintf(chains_file, "\n");
  fprintf(chains_file, "rank | chain_<id> | expensive=<kind> | dep_regs: <rd_L>, "
          "<rd_E> | occurred <N> times\n");
  fprintf(chains_file, "  <pc>  <instr>  # (L) producer  [sym | file]\n");
  fprintf(chains_file, "  <pc>  <instr>  # (E) producer  [sym | file]\n");
  fprintf(chains_file, "  <pc>  <instr>  # (J) consumer  [sym | file]\n\n");

  for (size_t rank = 0; rank < analysis->chain_count; rank++) {
    chain_entry_t *entry = analysis->chains[rank];
    char *sym_l = NULL;
    char *sym_e = NULL;
    char *sym_j = NULL;
    char *file_l = NULL;
    char *file_e = NULL;
    char *file_j = NULL;

    get_symbol_info_by_addr(entry->long_addr, &sym_l, NULL, &file_l);
    get_symbol_info_by_addr(entry->expensive_addr, &sym_e, NULL, &file_e);
    get_symbol_info_by_addr(entry->join_addr, &sym_j, NULL, &file_j);

    fprintf(chains_file,
            "%4zu | chain_%d | expensive=%-4s | dep_regs: %s, %s | occurred "
            "%" PRIu64 " times (%.4f%%)\n",
            rank + 1, entry->chain_id, expensive_kind_name(entry->expensive_kind),
            reg_name(entry->dep_reg_l), reg_name(entry->dep_reg_e), entry->count,
            analysis->total_occurrences > 0
                ? (100.0 * (double)entry->count /
                   (double)analysis->total_occurrences)
                : 0.0);
    fprintf(chains_file, "  0x%016" PRIxPTR "  %-36s # (L) producer  [%s | %s]\n",
            entry->long_addr, entry->long_text,
            sym_l != NULL ? sym_l : "(none)",
            file_l != NULL ? file_l : "(unknown)");
    fprintf(chains_file, "  0x%016" PRIxPTR "  %-36s # (E) producer  [%s | %s]\n",
            entry->expensive_addr, entry->expensive_text,
            sym_e != NULL ? sym_e : "(none)",
            file_e != NULL ? file_e : "(unknown)");
    fprintf(chains_file, "  0x%016" PRIxPTR "  %-36s # (J) consumer  [%s | %s]\n",
            entry->join_addr, entry->join_text,
            sym_j != NULL ? sym_j : "(none)",
            file_j != NULL ? file_j : "(unknown)");
    fprintf(chains_file, "\n");

    free(sym_l);
    free(sym_e);
    free(sym_j);
    free(file_l);
    free(file_e);
    free(file_j);
  }

  fclose(chains_file);
  fprintf(stderr, "[dep_chain] chains.txt written.\n");
}

static void write_hotspots(const analysis_data_t *analysis) {
  FILE *hotspots_file = fopen("hotspots.txt", "w");

  if (hotspots_file == NULL) {
    perror("[dep_chain] hotspots.txt");
    return;
  }

  fprintf(hotspots_file, "================================================\n");
  fprintf(hotspots_file, " LEJ Dependency Chain Detector -- Hotspot Report\n");
  fprintf(hotspots_file, "================================================\n\n");
  fprintf(hotspots_file, "Each count below is the number of LEJ chain "
          "occurrences in which a static instruction participated.\n");
  fprintf(hotspots_file, "Expensive-kind counts track which expensive-op "
          "family each chain occurrence used.\n\n");

  write_hotspot_section(hotspots_file, "[Overall Instruction Hotspots]",
                        analysis->hotspots_by_total, analysis->hotspot_count,
                        HOTSPOT_ROLE_TOTAL, analysis->total_occurrences);
  write_hotspot_section(hotspots_file, "[Long Producer Hotspots]",
                        analysis->hotspots_by_long, analysis->hotspot_count,
                        HOTSPOT_ROLE_LONG, analysis->total_occurrences);
  write_hotspot_section(hotspots_file, "[Expensive Producer Hotspots]",
                        analysis->hotspots_by_expensive, analysis->hotspot_count,
                        HOTSPOT_ROLE_EXPENSIVE, analysis->total_occurrences);
  write_hotspot_section(hotspots_file, "[Join Consumer Hotspots]",
                        analysis->hotspots_by_join, analysis->hotspot_count,
                        HOTSPOT_ROLE_JOIN, analysis->total_occurrences);

  fclose(hotspots_file);
  fprintf(stderr, "[dep_chain] hotspots.txt written.\n");
}

int dependency_checker_pre_thread(mambo_context *ctx) {
  thread_data_t *t_data = (thread_data_t *)mambo_alloc(ctx, sizeof(thread_data_t));

  assert(t_data != NULL);
  memset(t_data, 0, sizeof(thread_data_t));

  t_data->chain_map = (mambo_ht_t *)mambo_alloc(ctx, sizeof(mambo_ht_t));
  assert(t_data->chain_map != NULL);
  assert(mambo_ht_init(t_data->chain_map, CHAIN_MAP_INIT, 0, 80, true) == 0);
  assert(mambo_set_thread_plugin_data(ctx, t_data) == MAMBO_SUCCESS);

  return 0;
}

int dependency_checker_post_thread(mambo_context *ctx) {
  thread_data_t *t_data = (thread_data_t *)mambo_get_thread_plugin_data(ctx);

  assert(t_data != NULL);

  atomic_increment_u64(&g_total_instr, t_data->total_instr);
  atomic_increment_u64(&g_total_long, t_data->total_long);
  atomic_increment_u64(&g_total_expensive, t_data->total_expensive);
  for (int kind = EXPENSIVE_KIND_MUL; kind < EXPENSIVE_KIND_COUNT; kind++) {
    atomic_increment_u64(&g_total_expensive_by_kind[kind],
                         t_data->total_expensive_by_kind[kind]);
  }

  fprintf(stderr, "[dep_chain] thread %d exited - total=%" PRIu64
          " long=%" PRIu64 " expensive=%" PRIu64 "\n",
          mambo_get_thread_id(ctx), t_data->total_instr,
          t_data->total_long, t_data->total_expensive);

  if (t_data->chain_map != NULL) {
    for (size_t index = 0; index < t_data->chain_map->size; index++) {
      if (t_data->chain_map->entries[index].key == 0) {
        continue;
      }

      local_chain_counter_t *entry =
          (local_chain_counter_t *)t_data->chain_map->entries[index].value;
      for (; entry != NULL; entry = entry->next) {
        atomic_increment_u64(&entry->chain->count, entry->count);
      }
    }

    free(t_data->chain_map->entries);
    pthread_mutex_destroy(&t_data->chain_map->lock);
    mambo_free(ctx, t_data->chain_map);
  }

  mambo_free(ctx, t_data);
  return 0;
}

int dependency_checker_pre_bb(mambo_context *ctx) {
  thread_data_t *t_data = (thread_data_t *)mambo_get_thread_plugin_data(ctx);

  if (t_data != NULL) {
    t_data->window_count = 0;
  }

  return 0;
}

int dependency_checker_pre_inst(mambo_context *ctx) {
  thread_data_t *t_data = (thread_data_t *)mambo_get_thread_plugin_data(ctx);
  inst_info_t curr_inst;

  if (t_data == NULL) {
    return 0;
  }

  emit_counter64_incr(ctx, &t_data->total_instr, 1);
  decode_inst_info(ctx, &curr_inst);

  if (curr_inst.iclass == INST_LONG) {
    emit_counter64_incr(ctx, &t_data->total_long, 1);
  } else if (curr_inst.iclass == INST_EXPENSIVE) {
    emit_counter64_incr(ctx, &t_data->total_expensive, 1);
    if (curr_inst.expensive_kind > EXPENSIVE_KIND_NONE &&
        curr_inst.expensive_kind < EXPENSIVE_KIND_COUNT) {
      emit_counter64_incr(ctx,
                          &t_data->total_expensive_by_kind[curr_inst.expensive_kind],
                          1);
    }
  }

  if (curr_inst.src_reg[0] >= 0 && curr_inst.src_reg[1] >= 0) {
    int window_count = t_data->window_count;
    bool found = false;

    for (int long_idx = 0; long_idx < window_count && !found; long_idx++) {
      if (t_data->window[long_idx].iclass != INST_LONG) {
        continue;
      }

      for (int expensive_idx = 0; expensive_idx < window_count && !found;
           expensive_idx++) {
        int rd_l = -1;
        int rd_e = -1;
        local_chain_counter_t *entry;

        if (expensive_idx == long_idx ||
            t_data->window[expensive_idx].iclass != INST_EXPENSIVE) {
          continue;
        }

        if (!detect_lej(t_data->window, window_count, long_idx, expensive_idx,
                        &curr_inst, &rd_l, &rd_e)) {
          continue;
        }

        entry = lookup_or_create_local_chain_counter(
            ctx, t_data, &t_data->window[long_idx],
            &t_data->window[expensive_idx], &curr_inst, rd_l, rd_e);
        emit_counter64_incr(ctx, &entry->count, 1);
        found = true;
      }
    }
  }

  if (t_data->window_count < WINDOW_SIZE) {
    t_data->window[t_data->window_count++] = curr_inst;
  } else {
    memmove(&t_data->window[0], &t_data->window[1],
            (WINDOW_SIZE - 1) * sizeof(inst_info_t));
    t_data->window[WINDOW_SIZE - 1] = curr_inst;
  }

  return 0;
}

int dependency_checker_exit(mambo_context *ctx) {
  analysis_data_t analysis;

  (void)ctx;

  prepare_analysis_data(&analysis);
  write_stats(&analysis);
  write_chains(&analysis);
  write_hotspots(&analysis);
  free_analysis_data(&analysis);
  return 0;
}

__attribute__((constructor)) void dependency_checker_init(void) {
  mambo_context *ctx = mambo_register_plugin();
  int ret;

  assert(ctx != NULL);

  fprintf(stderr, "[dep_chain] plugin loaded\n");

  ret = mambo_register_pre_thread_cb(ctx, dependency_checker_pre_thread);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_post_thread_cb(ctx, dependency_checker_post_thread);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_pre_basic_block_cb(ctx, dependency_checker_pre_bb);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_pre_inst_cb(ctx, dependency_checker_pre_inst);
  assert(ret == MAMBO_SUCCESS);

  ret = mambo_register_exit_cb(ctx, dependency_checker_exit);
  assert(ret == MAMBO_SUCCESS);
}

#endif
