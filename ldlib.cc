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

static const int max_offload = 10;
static struct log *log_list;
static size_t log_index;
static int __thread _in_trace = 0;
static char empty_data[32];

#if !defined(PROF) && !defined(PRERUN)
static uint64_t offload_candidates[max_offload];
static int offload_count = 0;
#endif

void __attribute__((constructor)) m_init(void);
static void *(*_malloc)(size_t);
static void *(*_calloc)(size_t, size_t);
static void (*_free)(void *);
static int (*main_orig)(int, char **, char **);
static int safe = 0;

struct log {
    uint64_t rdt;
    uint64_t addr;
    uint64_t size;
    uint64_t entry_type;  // 0 free 1 malloc >=100 mmap
    uint64_t call_stack_size;
    uint64_t digest;
    void *call_stack_strings[10];
};

#ifdef PRERUN
#define MAX_CTXS 512
struct {
    uint64_t sizes[MAX_CTXS];
    uint64_t digests[MAX_CTXS];
    void *call_stacks[MAX_CTXS][10];
    size_t index;
} alloc_ctxs;
#endif

struct stack_frame {
    struct stack_frame *next_frame;
    unsigned long return_address;
};

bool is_offload(uint64_t digest) {
#pragma GCC unroll max_offload
    for (size_t i = 0; i < max_offload; ++i) {
        if (offload_candidates[i] == 0) break;
        if (offload_candidates[i] == digest) return true;
    }
    return false;
}

struct log *acquire_log() {
    if (!log_list)
        log_list = (struct log *)_malloc(sizeof(*log_list) * ARR_SIZE);
    if (log_index >= ARR_SIZE) return NULL;

    struct log *l = &log_list[log_index++];
    return l;
}

int bktrace(size_t *size, void **strings, uint64_t *digest) {
    if (_in_trace || !size || !strings) return 1;

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
        *size = i + 1;
        digest_ = digest_ + frame->return_address;
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
#ifdef PROF
    void *addr = _malloc(size);
    if (!_in_trace) {
        struct log *log_item = acquire_log();
        if (log_item) {
            rdtscll(log_item->rdt);
            log_item->addr = (uint64_t)addr;
            log_item->size = size;
            log_item->entry_type = 1;
            bktrace(&log_item->call_stack_size, log_item->call_stack_strings,
                    &log_item->digest);
        }
    }
    return addr;
#else
    uint64_t digest;
    size_t call_stack_size;
    void *call_stack[10];
    if (!_in_trace) bktrace(&call_stack_size, call_stack, &digest);
#ifdef PRERUN
    const size_t alloc_ctx_index = alloc_ctxs.index;
    bool present = false;
    for (size_t i = 0; i < alloc_ctx_index; ++i) {
        if (alloc_ctxs.digests[i] == digest) {
            present = true;
            break;
        }
    }
    if (!present) {
        alloc_ctxs.sizes[alloc_ctx_index] = size;
        alloc_ctxs.digests[alloc_ctx_index] = digest;
        memcpy(alloc_ctxs.call_stacks[alloc_ctx_index], call_stack,
               call_stack_size * sizeof(void *));
        alloc_ctxs.index++;
    }
    return _malloc(size);
#else
    if ((safe == 1) && is_offload(digest))
        return memkind_malloc(MEMKIND_DAX_KMEM, size);
    else
        return _malloc(size);

#endif
#endif
}

extern "C" void *calloc(size_t num, size_t size) {
#ifdef PROF
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
            bktrace(&log_item->call_stack_size, log_item->call_stack_strings,
                    &(log_item->digest));
        }
    }

    return addr;
#endif
    uint64_t digest;
    if (!_in_trace) bktrace(NULL, NULL, &digest);
#ifdef PRERUN
    const size_t alloc_ctx_index = alloc_ctxs.index;
    bool present = false;
    for (size_t i = 0; i < alloc_ctx_index; ++i) {
        if (alloc_ctxs.digests[i] == digest) {
            present = true;
            break;
        }
    }
    if (!present) {
        alloc_ctxs.sizes[alloc_ctx_index] = size;
        alloc_ctxs.digests[alloc_ctx_index] = digest;
        alloc_ctxs.index++;
    }
#else
    if (safe == 1) {
        return memkind_calloc(MEMKIND_DAX_KMEM, num, size);
    }
#endif
    void *addr;
    if (!_calloc) {
        memset(empty_data, 0, sizeof(*empty_data));
        addr = empty_data;
    } else {
        addr = _calloc(num, size);
    }
    return addr;
}

extern "C" void free(void *p) {
    if (!_free) m_init();
#ifdef PROF
    if (!_in_trace && _free) {
        struct log *log_item = acquire_log();
        if (log_item) {
            rdtscll(log_item->rdt);
            log_item->addr = (uint64_t)p;
            log_item->size = 0;
            log_item->entry_type = 2;
            bktrace(&log_item->call_stack_size, log_item->call_stack_strings,
                    &log_item->digest);
        }
    }
    _free(p);
#else
    if (safe == 1) {
        if (p < sbrk(0))
            _free(p);
        else
            memkind_free(MEMKIND_DAX_KMEM, p);
    } else {
        _free(p);
    }
#endif
}

extern "C" int __attribute__((destructor)) dump_heap_events() {
#if defined(PROF) || defined(PRERUN)
    const char *env_out_path = getenv("OUT_PATH");
    const char *out_path =
        (env_out_path != NULL) ? env_out_path : "./heap-events.%d";

    char buff[125];
    snprintf(buff, sizeof(buff), out_path, (int)syscall(186));

    FILE *dump = fopen(buff, "a+");
    if (!dump) {
        fprintf(stderr, "error: failed to open %s\n", buff);
        exit(EXIT_FAILURE);
    }

#ifdef PROF
    fprintf(dump, "rdt\tdigest\tcall_stack\tsize\taddr\tentry_type\n");

    for (size_t j = 0; j < log_index; ++j) {
        struct log *l = &log_list[j];

        char call_stack_buf[1024] = {0};
        size_t offset = 0;
        offset += snprintf(call_stack_buf + offset,
                           sizeof(call_stack_buf) - offset, "[");

        for (size_t k = 0; k < l->call_stack_size && l->call_stack_strings[k];
             ++k) {
            offset += snprintf(call_stack_buf + offset,
                               sizeof(call_stack_buf) - offset, "%p,",
                               l->call_stack_strings[k]);
        }

        if (offset > 1 && call_stack_buf[offset - 1] == ',')
            call_stack_buf[offset - 1] = ']';
        else
            strncat(call_stack_buf, "]", sizeof(call_stack_buf) - offset);

        fprintf(dump, "%lu\t%lu\t%s\t%d\t%lx\t%d\n", l->rdt, l->digest,
                call_stack_buf, (int)l->size, (unsigned long)l->addr,
                (int)l->entry_type);
    }
#else
    fprintf(dump, "digest,size,call_stack\n");
    for (size_t i = 0; i < alloc_ctxs.index; i++) {
        char call_stack_buf[1024] = {0};
        size_t offset = 0;
        offset += snprintf(call_stack_buf + offset,
                           sizeof(call_stack_buf) - offset, "[");

        for (size_t k = 0; k < 10 && alloc_ctxs.call_stacks[i][k]; ++k) {
            offset += snprintf(call_stack_buf + offset,
                               sizeof(call_stack_buf) - offset, "%p;",
                               alloc_ctxs.call_stacks[i][k]);
        }

        if (offset > 1 && call_stack_buf[offset - 1] == ';')
            call_stack_buf[offset - 1] = ']';
        else
            strncat(call_stack_buf, "]", sizeof(call_stack_buf) - offset);

        fprintf(dump, "%ld,%ld,%s\n", alloc_ctxs.digests[i],
                alloc_ctxs.sizes[i], call_stack_buf);
    }
#endif
    fclose(dump);
#endif
    return 0;
}

void __attribute__((constructor)) m_init(void) {
    _malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
    _calloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
    _free = (void (*)(void *))dlsym(RTLD_NEXT, "free");

#if !defined(PROF) && !defined(PRERUN)
    const char *env_name = "OFFLOAD_CANDIDATES";
    char *env = getenv(env_name);
    if (env == NULL) return;

    char *input = strdup(env);
    if (input == NULL) return;

    char *token = strtok(input, ",");
    while (token != NULL && offload_count < max_offload) {
        offload_candidates[offload_count++] = atoi(token);
        token = strtok(NULL, ",");
    }
    _free(input);
#endif
}

int main_hook(int argc, char **argv, char **envp) {
    safe = 1;
    int ret = main_orig(argc, argv, envp);
    return ret;
}

extern "C" int __libc_start_main(int (*main)(int, char **, char **), int argc,
                                 char **argv,
                                 int (*init)(int, char **, char **),
                                 void (*fini)(void), void (*rtld_fini)(void),
                                 void *stack_end) {
    main_orig = main;
    typeof(&__libc_start_main) orig =
        (int (*)(int (*)(int, char **, char **), int, char **,
                 int (*)(int, char **, char **), void (*)(), void (*)(),
                 void *))dlsym(RTLD_NEXT, "__libc_start_main");
    return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}
