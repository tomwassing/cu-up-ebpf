LIBS = bpf

all: hello.bpf.o hello.skel.h test

hello.bpf.o: hello.bpf.c
	clang -target bpf -Wall -O2 -c $<

hello.skel.h: hello.bpf.o
	bpftool gen skeleton $< > $@

test: test.c
	gcc -Wall -o $@ $< -l$(LIBS)
	

.PHONY:
clean:
	rm -rf hello.bpf.o
	rm -rf hello.skel.h
	rm -rf test