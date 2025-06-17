/* Max number of malloc per core */
#define ARR_SIZE 1000000000

/* Use Frame Pointers to compute the stack trace (faster) */
#define USE_FRAME_POINTER 1

/* Stack trace length */
#define CALLCHAIN_SIZE 32

struct log {
    uint64_t rdt;
    uint64_t addr;
    uint64_t size;
    uint64_t entry_type;  // 0 free 1 malloc >=100 mmap
    uint64_t call_stack_size;
    uint64_t digest;
    void *call_stack_strings[10];
};

struct stack_frame {
    struct stack_frame *next_frame;
    uint64_t return_address;
};

#ifdef PRERUN
#define MAX_CTXS 4096
struct {
    uint64_t counts[MAX_CTXS];
    uint64_t digests[MAX_CTXS];
    void *call_stacks[MAX_CTXS][10];
    size_t index;
} alloc_ctxs;
#endif
