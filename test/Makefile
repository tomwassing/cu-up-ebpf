all: vmlinux xdp_pdcp_rx.o xdp_pdcp_rx.skel.h test

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

xdp_pdcp_rx.o: ../rx/xdp_pdcp_rx.c
	clang -target bpf -Wall -O2 -c $<

xdp_pdcp_rx.skel.h: xdp_pdcp_rx.o
	bpftool gen skeleton $< > $@
	sed -i '/mmaped/d' xdp_pdcp_rx.skel.h # TODO: fix

test: test.c
	gcc -Wall -o $@ $< -lbpf

.PHONY:
clean:
	rm -rf vmlinux.h
	rm -rf xdp_pdcp_rx.o
	rm -rf xdp_pdcp_rx.skel.h
	rm -rf test
