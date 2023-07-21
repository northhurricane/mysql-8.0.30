#ifndef JEMALLOC_INTERNAL_COUNTER_H
#define JEMALLOC_INTERNAL_COUNTER_H
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
#define _Atomic(X) std::atomic<X>
#endif
#define UT_ARR_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#ifndef thread_local
#if __STDC_VERSION__ >= 201112 && !defined __STDC_NO_THREADS__
#define thread_local _Thread_local
#elif defined _WIN32 && (defined _MSC_VER || defined __ICL || \
                         defined __DMC__ || defined __BORLANDC__)
#define thread_local __declspec(thread)
/* note that ICC (linux) and Clang are covered by __GNUC__ */
#elif defined __GNUC__ || defined __SUNPRO_C || defined __xlC__
#define thread_local __thread
#else
#error "Cannot define thread_local"
#endif
#endif

#define ulonglong unsigned long long

extern unsigned long config_chunk_size;
extern thread_local int64_t je_totalsize;
extern thread_local int64_t last_global_mem_cnt;
extern thread_local int64_t last_global_mem_snapshot;
extern _Atomic(int64_t) je_server_totalsize;
extern bool config_mon;
#define DIFF(x, y) (x > y ? x - y : y - x)

__attribute__((always_inline)) static inline void inc_thr_and_global_memory(
    unsigned long long size, bool is_bp) {
  je_totalsize += size;
  // Calculate the absolute difference between je_totalsize and
  // last_global_mem_cnt
  unsigned long d = DIFF(je_totalsize, last_global_mem_cnt);
  if (d >= config_chunk_size) {
    // If the difference is greater than the chunk size, update the global
    // counter Since we are increasing memory, no negative value is possible
    je_server_totalsize += d;
    last_global_mem_cnt = je_totalsize;
    last_global_mem_snapshot = je_server_totalsize;
  }
}

__attribute__((always_inline)) static inline void dec_thr_and_global_memory(
    unsigned long long size, bool is_bp) {
  je_totalsize -= size;
  // Calculate the absolute difference between je_totalsize and
  // last_global_mem_cnt
  unsigned long d = DIFF(je_totalsize, last_global_mem_cnt);
  if (d >= config_chunk_size) {
    // If the difference is greater than the chunk size, update the global
    // counter Since we are decreasing memory, no positive value is possible
    last_global_mem_cnt = je_totalsize;
    je_server_totalsize -= d;
    last_global_mem_snapshot = je_server_totalsize;
  }
}
#endif