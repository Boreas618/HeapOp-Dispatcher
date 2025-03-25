CFLAGS=-Wall -g -ggdb3 -O0
LDFLAGS=-lmemkind

.PHONY: all clean
all: makefile.dep ldlib.so test

makefile.dep: *.[Cch]
	for i in *.[Cc]; do gcc -MM "$${i}" ${CFLAGS}; done > $@
	
-include makefile.dep

ldlib.so: ldlib.c
	g++ -fPIC ${CFLAGS} -c ldlib.c
	g++ -shared -Wl,-soname,libpmalloc.so -o ldlib.so ldlib.o -ldl -lpthread -lmemkind

clean:
	rm -f *.o *.so test makefile.dep

