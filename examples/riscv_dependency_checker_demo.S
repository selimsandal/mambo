/*
  Demo workload for plugins/dependency_checker.c.

  The loop below intentionally creates three LEJ patterns:
    load -> mul -> add
    load -> div -> add
    load -> rem -> add

  This gives stats.txt, chains.txt, and hotspots.txt non-trivial output,
  including the expensive-op family breakdowns. The per-chain and per-hotspot
  counts should match the loop trip count exactly. The global executed totals in
  stats.txt can be slightly higher because process startup and teardown code may
  also execute expensive instructions before main().
*/

    .section .rodata
    .align 3
values:
    .dword 3
    .dword 9
    .dword 11

    .text
    .globl main
main:
    addi sp, sp, -16
    sd ra, 8(sp)

    la s0, values
    li s1, 20000
    li s2, 400000
    li s3, 7
    li s4, 0

.Lloop:
    ld t0, 0(s0)
    mul t1, s1, s1
    add t2, t0, t1
    add s4, s4, t2

    ld t3, 8(s0)
    div t4, s2, s3
    add t5, t3, t4
    add s4, s4, t5

    ld t6, 16(s0)
    rem a0, s2, s3
    add a1, t6, a0
    add s4, s4, a1

    addi s1, s1, -1
    addi s2, s2, -13
    bnez s1, .Lloop

    ld ra, 8(sp)
    addi sp, sp, 16
    li a0, 0
    ret
