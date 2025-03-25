#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define __USE_GNU
#include <assert.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <memkind.h>
#include <numa.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define OUT_PATH "/mnt/sda4/run/redis/heap-events.%d"

/* Max number of malloc per core */
#define ARR_SIZE 1000000000

/* Use Frame Pointers to compute the stack trace (faster) */
#define USE_FRAME_POINTER 1

/* Stack trace length */
#define CALLCHAIN_SIZE 32

#ifdef __x86_64__
#define rdtscll(val)                                                 \
    {                                                                \
        unsigned int __a, __d;                                       \
        asm volatile("rdtsc" : "=a"(__a), "=d"(__d));                \
        (val) = ((unsigned long)__a) | (((unsigned long)__d) << 32); \
    }

#else
#define rdtscll(val) __asm__ __volatile__("rdtsc" : "=A"(val))
#endif

#define get_bp(bp) asm("movq %%rbp, %0" : "=r"(bp) :)

static struct log *log_list;
static size_t log_index;
static int __thread _in_trace = 0;
static char empty_data[32];

void __attribute__((constructor)) m_init(void);
static void *(*_malloc)(size_t);
static void *(*_calloc)(size_t, size_t);
static void (*_free)(void *);

struct log {
    uint64_t rdt;
    uint64_t addr;
    uint64_t size;
    uint64_t entry_type;  // 0 free 1 malloc >=100 mmap
    uint64_t callchain_size;
    uint64_t digest;
    void *callchain_strings[10];
};

struct stack_frame {
    struct stack_frame *next_frame;
    unsigned long return_address;
};

struct log *acquire_log() {
    if (!log_list)
        log_list = (struct log *)_malloc(sizeof(*log_list) * ARR_SIZE);
    if (log_index >= ARR_SIZE) return NULL;

    struct log *l = &log_list[log_index++];
    return l;
}

int bktrace(size_t *size, void **strings, uint64_t *digest) {
    if (_in_trace) return 1;
    if (!size) return 1;
    if (!strings) return 1;
    _in_trace = 1;

    /**
     * A digest is generated for the call chain returned by this function.
     * This fosters call chain-specific operations later.
     */
    uint64_t digest_ = 0;

#if USE_FRAME_POINTER
    struct stack_frame *frame;

    /**
     * Note that we assume the application is compiled with -no-pie. Therefore,
     * the entries in the call chain should be a relatively low address
     * (e.g., 0x40125a) instead of that in a pie binary (e.g., 0x558d8849626d).
     */
    get_bp(frame);

    /**
     * The initial stack frame is skipped since it is in the dynamically linked
     * area.
     */
    frame = frame->next_frame;

    for (int i = 0; i < CALLCHAIN_SIZE; i++) {
        if (!frame) break;
        /**
         * We only capture call chain in the text section.
         */
        if (frame->return_address >= 0xffffff || frame->return_address == 0)
            break;
        strings[i] = (void *)frame->return_address;
        digest_ = digest_ + frame->return_address;
        *size = i + 1;
        frame = frame->next_frame;
    }

#else
    *size = backtrace(strings, 10);
#endif

    *digest = digest_;
    _in_trace = 0;
    return 0;
}

extern "C" void *malloc(size_t size) {
    if (!_malloc) m_init();
    void *addr = _malloc(size);
    if (!_in_trace) {
        struct log *log_item = acquire_log();
        if (log_item) {
            rdtscll(log_item->rdt);
            log_item->addr = (uint64_t)addr;
            log_item->size = size;
            log_item->entry_type = 1;
            bktrace(&log_item->callchain_size, log_item->callchain_strings,
                    &log_item->digest);
        }
    }
    return addr;
}

extern "C" void *calloc(size_t num, size_t size) {
    void *addr;
    if (!_calloc) {
        memset(empty_data, 0, sizeof(*empty_data));
        addr = empty_data;
    } else {
        addr = _calloc(num, size);
    }
    if (!_in_trace && _calloc) {
        struct log *log_item = acquire_log();
        if (log_item) {
            rdtscll(log_item->rdt);
            log_item->addr = (uint64_t)addr;
            log_item->size = num * size;
            log_item->entry_type = 1;
            bktrace(&log_item->callchain_size, log_item->callchain_strings,
                    &(log_item->digest));
        }
    }

    return addr;
}

extern "C" void free(void *p) {
    if (!_free) m_init();
    if (!_in_trace && _free) {
        struct log *log_item = acquire_log();
        if (log_item) {
            rdtscll(log_item->rdt);
            log_item->addr = (uint64_t)p;
            log_item->size = 0;
            log_item->entry_type = 2;
            bktrace(&log_item->callchain_size, log_item->callchain_strings,
                    &log_item->digest);
        }
    }
    _free(p);
}

extern "C" int dump_heap_events() {
    char buff[125];
    sprintf(buff, OUT_PATH, (int)syscall(186));

    FILE *dump = fopen(buff, "a+");
    if (!dump) {
        fprintf(stderr, "error: failed to open %s\n", buff);
        exit(EXIT_FAILURE);
    }

    fprintf(dump, "rdt\tdigest\tcall_chain\tsize\taddr\tentry_type\n");
    for (size_t j = 0; j < log_index; j++) {
        struct log *l = &log_list[j];
        fprintf(dump, "%lu\t", l->rdt);
        fprintf(dump, "%lu\t", l->digest);
        fprintf(dump, "[");
        for (size_t k = 0; k < l->callchain_size; k++) {
            if (l->callchain_strings[k] == NULL) break;
            fprintf(dump, "%p,", l->callchain_strings[k]);
        }
        fprintf(dump, "]\t");
        fprintf(dump, "%d\t%lx\t%d\n", (int)l->size, (long unsigned)l->addr,
                (int)l->entry_type);
    }
    return 0;
}

void __attribute__((constructor)) m_init(void) {
    _malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
    _calloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
    _free = (void (*)(void *))dlsym(RTLD_NEXT, "free");
}
