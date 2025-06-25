/* deep_aac_mul_sym.c – DFS-vs-BFS demo with symbolic AAC size
 * gcc -O0 -g -static -o deep_aac_mul_sym deep_aac_mul_sym.c
 */

#include <stdio.h>
#include <stdlib.h>

#define DEPTH 10
static const unsigned mask[DEPTH] = {
    1u<<0, 1u<<1, 1u<<2, 1u<<3, 1u<<4,
    1u<<5, 1u<<6, 1u<<7, 1u<<8, 1u<<9
}

/* ---------- keeps BFS busy, unchanged ------------------------------ */
__attribute__((noinline))
static void dummy_noise(int lvl, unsigned x)
{
    if (x & (1u << (lvl + 10))) { volatile int a = x; }
    else                        { volatile int b = x + 1; }

    if (x & (1u << (lvl + 20))) { volatile int c = x; }
    else                        { volatile int d = x + 2; }

    if (x & (1u << (lvl + 30))) { volatile int e = x; }
    else                        { volatile int f = x + 3; }
}

/* ---------- the AAC—size is satisfiable to zero -------------------- */
__attribute__((noinline))
static void deep_aac(unsigned x)
{
    /* size = x * ((x & 1) ^ 1)
       └─ When LSB of x is 1 (true on the deep path), factor is 0 → size = 0
          Otherwise the factor is 1 → size = x (non-zero)
       Thus the constraint system *allows* malloc(0) but does not *force* it. */
    size_t sz = x * ((x & 1u) ^ 1u);      // ★ symbolic, satisfiable to 0
    void  *p  = malloc(sz);               // ★ AAC here
    if (p) free(p);
}

/* ---------- deterministic deep path + width noise ------------------ */
static void dive(int level, unsigned x)
{
    if (level == DEPTH) {                 /* leaf → trigger AAC */
        deep_aac(x);
        return;
    }

    if (x & mask[level])                  /* DFS follows this first */
        dive(level + 1, x);

    dummy_noise(level, x);                /* BFS sinks cycles here */
}

int main(void)
{
    unsigned x;
    if (scanf("%u", &x) != 1) return 1;
    dive(0, x);
    return 0;
}
