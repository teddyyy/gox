CC = clang

objects += src/gox_user.o

libbpf_objects += libbpf/src/staticobjs/bpf.o \
		  libbpf/src/staticobjs/btf.o \
		  libbpf/src/staticobjs/libbpf_errno.o \
		  libbpf/src/staticobjs/libbpf_probes.o
libbpf_objects += libbpf/src/staticobjs/libbpf.o \
		  libbpf/src/staticobjs/netlink.o \
		  libbpf/src/staticobjs/nlattr.o \
		  libbpf/src/staticobjs/str_error.o
libbpf_objects += libbpf/src/staticobjs/hashmap.o \
		  libbpf/src/staticobjs/bpf_prog_linfo.o

CFLAGS += -Wall -Werror -Wno-pointer-sign -Wno-compare-distinct-pointer-types -I/build/root/usr/include/
LDFLAGS += -lelf

all: gox_user gox_kern goxctl

gox_user: libbpf $(objects)
	clang $(LDFLAGS) -o gox_user $(libbpf_objects) $(objects)

gox_kern: src/gox_kern.o
	clang \
	-D__BPF_TRACING__ \
	-Wall -Wextra \
	-Wno-compare-distinct-pointer-types \
	-Wno-sign-compare -O2 -emit-llvm -c src/gox_kern.c -o src/gox_kern.ll
	llc -march=bpf -filetype=obj src/gox_kern.ll -o src/gox_kern.o

goxctl: src/goxctl.c
	clang src/goxctl.c -o goxctl

libbpf:
	$(MAKE) -C libbpf/src

clean:
	$(MAKE) -C libbpf/src clean
	rm -f src/*.o src/*.ll
	rm -f gox_user
	rm -f goxctl

.PHONY: libbpf all
.DEFAULT: all

