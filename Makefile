CC = clang

objects += src/config.o src/client.c src/bfw.o

libbpf_static_objects += libbpf/src/staticobjs/bpf.o libbpf/src/staticobjs/btf.o libbpf/src/staticobjs/libbpf_errno.o libbpf/src/staticobjs/libbpf_probes.o
libbpf_static_objects += libbpf/src/staticobjs/libbpf.o libbpf/src/staticobjs/netlink.o libbpf/src/staticobjs/nlattr.o libbpf/src/staticobjs/str_error.o
libbpf_static_objects += libbpf/src/staticobjs/hashmap.o libbpf/src/staticobjs/bpf_prog_linfo.o

LDFLAGS += -lconfig -lelf -lz

all: bfw_loader bfw_filter
bfw_loader: libbpf $(objects)
	clang $(LDFLAGS) -o bfw $(libbpf_static_objects) $(objects) -lsodium -lpthread
bfw_filter: src/bfw_xdp.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/bfw_xdp.c -o src/bfw_xdp.bc
	llc -march=bpf -filetype=obj src/bfw_xdp.bc -o src/bfw_xdp.o
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -f src/*.o src/*.bc
	rm -f bfw
install:
	mkdir -p /etc/bfw/
	cp -n bfw.conf.example /etc/bfw/bfw.conf
	cp src/bfw_xdp.o /etc/bfw/bfw_xdp.o
	cp bfw /usr/bin/bfw
	cp -n other/bfw.service /etc/systemd/system/
.PHONY: libbpf all
.DEFAULT: all