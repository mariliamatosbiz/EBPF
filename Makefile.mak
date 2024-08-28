LLC ?= llc
CLANG ?= clang
CC ?= gcc

KERN_SOURCES := xdp_counter.c
KERN_OBJECTS := ${KERN_SOURCES:.c=.o}

CFLAGS := -g -O2 -Wall
LDFLAGS := -lbpf -lelf

all: xdp_counter.o xdp_loader

%.o: %.c
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

xdp_loader: xdp_loader.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f *.o *.ll xdp_loader