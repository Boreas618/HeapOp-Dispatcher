# HeapOp-Dispatcher

**HeapOp-Dispatcher** is a dynamic heap operation interceptor that overloads standard heap-related functions (e.g., `malloc`) and dispatches them to alternate implementations. For example, memory can be allocated on a remote NUMA node using `memkind_malloc` instead of the default local heap.

**HeapOp-Dispatcher** is adapted from [Memprof Library](https://github.com/Memprof/library).

## Features

Supports three runtime modes:

- **`DEFAULT`**: Overloads selected `malloc` calls and redirects them to `memkind_malloc` to allocate memory on a remote NUMA node.

- **`PROF`**: Profiles heap operations (`malloc`, `calloc`, `free`, etc.), collecting rich metadata including call stack (calling context), timestamp, allocation size (if applicable), operation type, etc.

- **`PRERUN`**: Extracts digests of call contexts for heap operations. These digests can later be passed to the `DEFAULT` mode to guide selective overloading.

## Build

To build the preloadable shared object `ldlib.so`, run:

```bash
make ldlib.so [MODE=PROF|PRERUN]
```

## Run

For `PROF` or `PRERUN` modes:

```bash
MEMKIND_DAX_KMEM_NODES=1 numactl --cpunodebind=0 env LD_PRELOAD=./ldlib.so <your_program>
```

For `DEFAULT` mode, in addition to the above, specify the offload candidates using:

```bash
export OFFLOAD_CANDIDATES=12345,6789
```

Here, `OFFLOAD_CANDIDATES` is a comma-separated list of digests (collected during `PRERUN`) representing call sites to be redirected to remote allocation.

### Redis Support
Redis uses a hack to determine the size of the allocated heap memory, which is incompatible with the memkind implementation. Therefore, if you want to use this tool with Redis, it is recommended to use [this fork of Redis](https://github.com/Boreas618/redis).
