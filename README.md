# CU-UP eBPF/XDP Implementation

<img src="./docs/desire6g-logo.svg" width="200">

This repository contains an CU-UP implementation in eBPF/XDP developed as part of WP4 of the [DESIRE6G](https://desire6g.eu) project. [DESIRE6G](https://desire6g.eu) is project coordinated by the University of Amsterdam, [Informatics Institute](https://ivi.uva.nl) and supported by the Smart Networks and Services Joint Undertaking (SNS JU). Funded by Horizon Europe research programme under Grant Agreement no. 101096466.


The WP4 provides the programmable data plane components of the DESIRE6G architecture that will enable flexible changes in data plane functionality and the rapid deployment of customized network functions. Furthermore, WP4 will develop a pervasive monitoring infrastructure to obtain real-time information about the network resources with configurable granularity.

## Features

- CO-RE (Compile Once – Run Everywhere)
- Ciphering // TODO
- Compression (ROHC) // TODO
- Integrity // Work in progress

## System Requirements
Ubuntu 22.04 LTS with kernel version 5.15.

## Dependencies
The main dependencies are `libxdp`, `libbpf`, `llvm`, `clang` and
`libelf`. `LLVM` and `clang` compiles our restricted-C programs into BPF-byte-code, which is stored in an ELF object file (`libelf`), that is loaded by `libbpf` into the kernel via the `bpf` syscall. XDP programs are managed by `libxdp` which implements the XDP multi-dispatch protocol. Finally, the kernel headers are required for compilation of the program.

```sh
sudo apt install cmake clang llvm libelf-dev libbpf-dev libpcap-dev build-essential linux-headers-$(uname -r) linux-tools-common linux-tools-generic tcpdump
```

### Netronome SmartNIC
The primary goal of the implementation is to hardware accelerate the CU-UP as part of WP4 of the [DESIRE6G](https://desire6g.eu) project. Hardware acceleration can be achieved by using the XDP offload mode. Currently, [Netronome](https://www.netronome.com) is the only hardware vendor that nativelly supports the XDP offload mode. The beta drivers for kernel version 5.15 can be found at:

https://help.netronome.com/support/solutions/articles/36000072604-software-development-nfp-toolchain

NOTE: Installing the Netronome SmartNIC drivers are not required to test or deploy, but is recommended to achieve performance gains.

## Usage

### Build
```sh
cmake -S . -B build
cmake --build build
```

### Tests
```sh
cmake -S . -B build
cmake --build build
cd build && ctest
```

### Deployment
```sh
sudo ip link set <INTERFACE> xdpdrv obj xdp_cu_up.o sec xdp_cu_up
```

### Deployment (hardware offloaded)
```sh
sudo ip link set <INTERFACE> xdpoffload obj xdp_cu_up.o sec xdp_cu_up
```

## Architecture
The implementation utilises the PDCP and SDAP implementation from [srsRAN](https://github.com/srsran/srsRAN_Project). In the srsRAN PDCP layer implementation RObust Header Compression (ROHC) is missing and is suplemented from the open source ROHC library ([rohc-lib.org](https://rohc-lib.org)).

## Challenges
The main challenges of the implementation was porting the srsRAN code to eBPF-compatbile C. The eBPF verifier is very strict and imposes serval restrictions on the code. The main restrictions are:

- **Safety checks on all (external, e.g., packets) memory accesses** - The original code never assumed eBPF would be used and therefore did not perform any safety checks. The solution was to add safety checks to all memory accesses. This was done by wrapping packet memory access by simply checking if the index would exceed the packet size. 
- **No dynamic memory allocation** - The verifier does not allow dynamic memory allocation. This is mainly an issue in the ciphering algorithm as it is difficult to determine the size of the output buffer. The solution was to use a fixed size buffer and limit the input size to the size of the buffer.
- **No unbounded loops** - The verifier limits the number of loop iterations to prevent infinite loops. In the code this mainly formed an issue in the integrity and ciphering algorithms as they use recursive functions. Removing the recursion and replacing it with a bounded loop solved the issue
- **No standard library** - We can't use the standard library as it is not available in the kernel. This formed a small obstacle as the srsRAN code uses the standard library for some basic functions. The solution was to implement the functions ourselves.


## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. Please make sure to update tests as appropriate.

## License

[AGPL v3.0](https://github.com/srsran/srsRAN_Project/blob/main/LICENSE)