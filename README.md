# CU-UP eBPF/XDP Implementation
This repository contains an CU-UP implementation in eBPF/XDP developed as part of the [DESIRE6G](https://desire6g.eu) project. [DESIRE6G](https://desire6g.eu) is project coordinated by the University of Amsterdam, [Informatics Institute](https://ivi.uva.nl) and supported by the Smart Networks and Services Joint Undertaking (SNS JU). Funded by Horizon Europe research programme under Grant Agreement no. 101096466.

## System Requirements
Ubuntu 22.04 LTS with kernel version 5.15.

## Dependencies
The main dependencies are `libxdp`, `libbpf`, `llvm`, `clang` and
`libelf`. `LLVM` and `clang` compiles our restricted-C programs into BPF-byte-code, which is stored in an ELF object file (`libelf`), that is loaded by `libbpf` into the kernel via the `bpf` syscall. XDP programs are managed by `libxdp` which implements the XDP multi-dispatch protocol. Finally, the kernel headers are required for compilation of the eBPF progran.

```sh
sudo apt install clang llvm libelf-dev libpcap-dev build-essential linux-headers-$(uname -r) linux-tools-common linux-tools-generic tcpdump
```

### Netronome SmartNIC
The primary goal of the implementation is to hardware accelerate the CU-UP as part of work package 4 of the [DESIRE6G](https://desire6g.eu) project. Hardware acceleration can be achieved by using the XDP offload mode. Currently, [Netronome](https://www.netronome.com) is the only hardware vendor that nativelly supports the XDP offload mode. The drivers for kernel version 5.15 can be found at:

https://help.netronome.com/support/solutions/articles/36000072604-software-development-nfp-toolchain

NOTE: Installing the SmartNIC drivers are not required to test or deploy, but is recommended to achieve performance gains.

## Building
```sh
cmake -S . -B build
cmake --build build
```


## Tests
```sh
cmake -S . -B build
cmake --build build
cd build && ctest
```

## Architecture
The implementation utilises the PDCP and SDAP implementation from [srsRAN](https://github.com/srsran/srsRAN_Project). In the srsRAN PDCP layer implementation RObust Header Compression (ROHC) is missing and is suplemented from the open source ROHC library ([rohc-lib.org](https://rohc-lib.org)).
