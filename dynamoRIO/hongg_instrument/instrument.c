#include "instrument.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

static feedback_t bbMapFb;
feedback_t* feedback = &bbMapFb;
uint32_t my_thread_no = 0;

int files_getTmpMapFlags(int flag, bool nocore) {
#if defined(MAP_NOSYNC)
    /*
     * Some kind of bug in FreeBSD kernel. Without this flag, the shm_open() memory will cause a lot
     * of troubles to the calling process when mmap()'d
     */
    flag |= MAP_NOSYNC;
#endif /* defined(MAP_NOSYNC) */
#if defined(MAP_HASSEMAPHORE)
    /* Our shared/mmap'd pages can have mutexes in them */
    flag |= MAP_HASSEMAPHORE;
#endif /* defined(MAP_HASSEMAPHORE) */
    /* Avoid mapping the memory lazily */
#if defined(MAP_PREFAULT_READ)
    flag |= MAP_PREFAULT_READ;
#endif /* defined(MAP_PREFAULT_READ) */
#if defined(MAP_POPULATE)
    flag |= MAP_POPULATE;
#endif /* defined(MAP_POPULATE) */
    if (nocore) {
#if defined(MAP_CONCEAL)
        flag |= MAP_CONCEAL;
#endif /* defined(MAP_CONCEAL) */
#if defined(MAP_NOCORE)
        flag |= MAP_NOCORE;
#endif /* defined(MAP_NOCORE) */
    }
    return flag;
}


static void initializeInstrument(void) {
    if (fcntl(_HF_LOG_FD, F_GETFD) != -1) {
        enum llevel_t ll = INFO;
        const char* llstr = getenv(_HF_LOG_LEVEL_ENV);
        if (llstr) {
            ll = atoi(llstr);
        }
    }

    char* my_thread_no_str = getenv(_HF_THREAD_NO_ENV);
    if (my_thread_no_str == NULL) {
        return;
    }
    my_thread_no = atoi(my_thread_no_str);

    if (my_thread_no >= _HF_THREAD_MAX) {
    }

    struct stat st;
    if (fstat(_HF_BITMAP_FD, &st) == -1) {
        return;
    }
    if (st.st_size != sizeof(feedback_t)) {
    }
    int mflags = files_getTmpMapFlags(MAP_SHARED, /* nocore= */ true);
    if ((feedback = mmap(NULL, sizeof(feedback_t), PROT_READ | PROT_WRITE, mflags, _HF_BITMAP_FD,
             0)) == MAP_FAILED) {
    }

    /* Reset coverage counters to their initial state */
    instrumentClearNewCov();
}

static __thread pthread_once_t localInitOnce = PTHREAD_ONCE_INIT;

__attribute__((constructor)) void hfuzzInstrumentInit(void) {
    pthread_once(&localInitOnce, initializeInstrument);
}

/* Reset the counters of newly discovered edges/pcs/features */
void instrumentClearNewCov() {
    feedback->pidFeedbackPc[my_thread_no] = 0U;
    feedback->pidFeedbackEdge[my_thread_no] = 0U;
    feedback->pidFeedbackCmp[my_thread_no] = 0U;
}

/*
 * -finstrument-functions
 */
void __cyg_profile_func_enter(void* func, void* caller) {
    register size_t pos =
        (((uintptr_t)func << 12) | ((uintptr_t)caller & 0xFFF)) & _HF_PERF_BITMAP_BITSZ_MASK;
    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

void __cyg_profile_func_exit(
    void* func , void* caller ) {
    return;
}

/*
 * -fsanitize-coverage=trace-pc
 */


static inline void hfuzz_trace_pc_internal(uintptr_t pc) {
    register uintptr_t ret = pc & _HF_PERF_BITMAP_BITSZ_MASK;
    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, ret);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}


void if_hfuzz_trace_pc_internal(uintptr_t pc){
    hfuzz_trace_pc_internal(pc);
}


void __sanitizer_cov_trace_pc(void) {
    hfuzz_trace_pc_internal((uintptr_t)__builtin_return_address(0));
}

void hfuzz_trace_pc(uintptr_t pc) {
    hfuzz_trace_pc_internal(pc);
}

/*
 * -fsanitize-coverage=trace-cmp
 */

void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}


void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

static inline void hfuzz_trace_cmp4_internal(
    uintptr_t pc, uint32_t Arg1, uint32_t Arg2) {
    uintptr_t pos = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
    hfuzz_trace_cmp4_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

static inline void hfuzz_trace_cmp8_internal(
    uintptr_t pc, uint64_t Arg1, uint64_t Arg2) {
    uintptr_t pos = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcountll(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
    hfuzz_trace_cmp8_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void hfuzz_trace_cmp8(uintptr_t pc, uint64_t Arg1, uint64_t Arg2) {
    hfuzz_trace_cmp8_internal(pc, Arg1, Arg2);
}

/*
 * Const versions of trace_cmp, we don't use any special handling for these
 *
 * For MacOS, these're weak aliases, as Darwin supports only them
 */

#if defined(_HF_ARCH_DARWIN)
#pragma weak __sanitizer_cov_trace_const_cmp1 = __sanitizer_cov_trace_cmp1
#pragma weak __sanitizer_cov_trace_const_cmp2 = __sanitizer_cov_trace_cmp2
#pragma weak __sanitizer_cov_trace_const_cmp4 = __sanitizer_cov_trace_cmp4
#pragma weak __sanitizer_cov_trace_const_cmp8 = __sanitizer_cov_trace_cmp8
#else
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp1")));
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp2")));
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp4")));
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp8")));
#endif /* defined(_HF_ARCH_DARWIN) */

/*
 * Cases[0] is number of comparison entries
 * Cases[1] is length of Val in bits
 */
void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t* Cases) {
    for (uint64_t i = 0; i < Cases[0]; i++) {
        uintptr_t pos = ((uintptr_t)__builtin_return_address(0) + i) % _HF_PERF_BITMAP_SIZE_16M;
        uint8_t v = (uint8_t)Cases[1] - __builtin_popcountll(Val ^ Cases[i + 2]);
        uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
        if (prev < v) {
            ATOMIC_SET(feedback->bbMapCmp[pos], v);
            ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
        }
    }
}

/*
 * -fsanitize-coverage=trace-div
 */
void __sanitizer_cov_trace_div8(uint64_t Val) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    uint8_t v = ((sizeof(Val) * 8) - __builtin_popcountll(Val));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

void __sanitizer_cov_trace_div4(uint32_t Val) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    uint8_t v = ((sizeof(Val) * 8) - __builtin_popcount(Val));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

/*
 * -fsanitize-coverage=indirect-calls
 */
void __sanitizer_cov_trace_pc_indir(uintptr_t callee) {
    register size_t pos1 = (uintptr_t)__builtin_return_address(0) << 12;
    register size_t pos2 = callee & 0xFFF;
    register size_t pos = (pos1 | pos2) & _HF_PERF_BITMAP_BITSZ_MASK;

    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

/*
 * In LLVM-4.0 it's marked (probably mistakenly) as non-weak symbol, so we need to mark it as weak
 * here
 */
__attribute__((weak)) void __sanitizer_cov_indir_call16(
    void* callee, void* callee_cache16[]) {
    register size_t pos1 = (uintptr_t)__builtin_return_address(0) << 12;
    register size_t pos2 = (uintptr_t)callee & 0xFFF;
    register size_t pos = (pos1 | pos2) & _HF_PERF_BITMAP_BITSZ_MASK;

    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

/*
 * -fsanitize-coverage=trace-pc-guard
 */
static bool guards_initialized = false;

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {
    guards_initialized = true;
    static uint32_t n = 1U;

    /* Make sure that the feedback struct is already mmap()'d */
    hfuzzInstrumentInit();

    /* If this module was already initialized, skip it */
    if (*start > 0) {
        return;
    }

    for (uint32_t* x = start; x < stop; x++, n++) {
        if (n >= _HF_PC_GUARD_MAX) {

        }
        /* If the corresponding PC was already hit, map this specific guard as uninteresting (0) */
        *x = ATOMIC_GET(feedback->pcGuardMap[n]) ? 0U : n;
    }

    /* Store number of guards for statistical purposes */
    if (ATOMIC_GET(feedback->guardNb) < n - 1) {
        ATOMIC_SET(feedback->guardNb, n - 1);
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
#if defined(__ANDROID__)
    // ANDROID: Bionic invokes routines that Honggfuzz wraps, before either
    //          *SAN or Honggfuzz have initialized.  Check to see if Honggfuzz
    //          has initialized -- if not, force *SAN to initialize (otherwise
    //          _strcmp() will crash, as it is *SAN-instrumented).
    //
    //          Defer all trace_pc_guard activity until trace_pc_guard_init is
    //          invoked via sancov.module_ctor in the normal process of things.
    if (!guards_initialized) {
        void __asan_init(void) __attribute__((weak));
        if (__asan_init) {
            __asan_init();
        }
        void __msan_init(void) __attribute__((weak));
        if (__msan_init) {
            __msan_init();
        }
        void __ubsan_init(void) __attribute__((weak));
        if (__ubsan_init) {
            __ubsan_init();
        }
        void __tsan_init(void) __attribute__((weak));
        if (__tsan_init) {
            __tsan_init();
        }
        return;
    }
#endif /* defined(__ANDROID__) */
    bool prev = ATOMIC_XCHG(feedback->pcGuardMap[*guard], true);
    if (prev == false) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackEdge[my_thread_no]);
    }
}

void instrumentUpdateCmpMap(uintptr_t addr, uint32_t v) {
    uintptr_t pos = addr % _HF_PERF_BITMAP_SIZE_16M;
    uint32_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}
