#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <bpf/bpf_endian.h>
#include "hello.skel.h"
#include "net/ethernet.h"
#include "linux/ip.h"
#include "netinet/tcp.h"


int main (int argc, char *argv[]) {
        struct __sk_buff skb = {0};
        struct hello_bpf *skel;
        int prog_fd, err = 0;

        // define our BPF_PROG_RUN options with our mock data.
        struct bpf_test_run_opts opts = {
                // required, or else bpf_prog_test_run_opts will fail
                .sz = sizeof(struct bpf_test_run_opts),
                // ctx is an skb in this case
                .ctx_in = &skb,
                .ctx_size_in = sizeof(skb),
                .repeat = 1
        };

        // load our fib lookup test program into the Kernel and return our
        // skeleton handle to it.
        skel = hello_bpf__open_and_load();
        if (!skel) {
                printf("[error]: failed to open and load skeleton: %d\n", err);
                return -1;
        }

        // get the prog_fd from the skeleton, and run our test.
        prog_fd = bpf_program__fd(skel->progs.xdp_prog_simple);
        err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err != 0) {
                printf("[error]: bpf test run failed: %d\n", err); // -1
                perror("bpf_prog_test_run_opts"); // bpf_prog_test_run_opts: Unknown error 524
                return -2;
        }

        printf("IT RAN!\n");

        return 0;
}