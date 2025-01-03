`xdpnf` is a tool that attaches to the Linux kernel's [XDP](https://www.iovisor.org/technology/xdp) hooks through [(e)BPF](https://ebpf.io/) for fast packet processing. This tool is designed with functions which is similar with [iptables](https://linux.die.net/man/8/iptables). Both IPv4 and **IPv6** are supported! The protocols currently supported are TCP, UDP, ICMP, ICMPV6.

This project draws inspiration from [xdp-firewall](https://github.com/gamemann/XDP-Firewall) and [xdp-filter](hhttps://github.com/xdp-project/xdp-tools/tree/master/xdp-filter).

## Building & Installation
Before building, ensure the following packages are installed. These packages are installed via `apt` (Ubuntu, Debian, etc.), but there should be similar package names in other package managers.

```bash
# Install buliding tools (in case your package manager doesn't have llvm and clang >= 14, see https://apt.llvm.org/)
# xdpnf may be built using llvm-12 and clang-12 (but I have not yet tested) 
sudo apt install -y llvm-14 clang-14 m4 build-essential

# Install dependencies.
sudo apt install -y libelf-dev libconfig-dev libc6-dev-i386 libpcap-dev gcc-multilib 

# You need tools for your kernel since we need BPFTool. If this doesn't work, I'd suggest building BPFTool from source (https://github.com/libbpf/bpftool).
sudo apt install -y linux-tools-$(uname -r)
```