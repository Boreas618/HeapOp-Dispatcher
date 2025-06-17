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

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
