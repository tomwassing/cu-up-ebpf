.PHONY: rx
CC = clang

all: rx

rx:
	mkdir -p ./build
	$(CC) -O2 -g -Wall -target bpf -c ./rx/xdp_pdcp_rx.c -o ./build/xdp_pdcp_rx.o

clean:
	rm -rf build
