CC = g++
MODE ?= DEFAULT

ifeq ($(MODE),PRERUN)
  CFLAGS_MODE = -DPRERUN
else ifeq ($(MODE),PROF)
  CFLAGS_MODE = -DPROF
else
  CFLAGS_MODE =
endif

CFLAGS = -Wall -g -ggdb3 -O0 -fPIC $(CFLAGS_MODE)
TEST_EXEC_CFLAGS = -no-pie -fno-omit-frame-pointer -g
LDFLAGS = -ldl -lpthread -lmemkind
TARGET = ldlib.so
TEST_EXEC = test_prog
TEST_SRC = tests/main.c
DEPS_FILE = makefile.dep
RESULTS_FILE = heap-events.* *.txt

.PHONY: all clean test

all: $(DEPS_FILE) $(TARGET) $(TEST_EXEC)

$(TARGET): ldlib.o
	$(CC) -shared -Wl,-soname,libpmalloc.so -o $@ $^ $(LDFLAGS)

ldlib.o: ldlib.cc
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_EXEC): $(TEST_SRC) $(TARGET)
	$(CC) $(TEST_EXEC_CFLAGS) -o $@ $(TEST_SRC)

test: $(TEST_EXEC)
	MEMKIND_DAX_KMEM_NODES=1 numactl --cpunodebind=0 env LD_PRELOAD=./$(TARGET) ./$(TEST_EXEC) 2>&1 >> results.txt

clean:
	rm -f *.o *.so $(TEST_EXEC) $(DEPS_FILE) $(RESULTS_FILE)
