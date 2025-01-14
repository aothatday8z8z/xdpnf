`xdpnf` is a firewall tool based on eBPF. This tool is designed with functions similar to [iptables](https://linux.die.net/man/8/iptables) but leverages the high-speed packet processing power of eBPF/XDP (`xdp` stands for eXpress Data Path, while `nf` stands for netfilter that inspired by nftables). Both IPv4 and **IPv6** are supported! The protocols currently supported are TCP, UDP, ICMP, and ICMPv6.

This project draws inspiration from [xdp-firewall](https://github.com/gamemann/XDP-Firewall) and [xdp-filter](https://github.com/xdp-project/xdp-tools/tree/master/xdp-filter).

## Building & Installation
`xdpnf` is written in C and need built from source code. Before building, ensure the following packages are installed. These packages are installed via `apt` (Ubuntu, Debian, etc.), but there should be similar package names in other package managers.

```bash
# Install buliding tools (in case your package manager doesn't have llvm and clang >= 14, see https://apt.llvm.org/)
# xdpnf may be built using llvm-12 and clang-12 (but I have not yet tested) 
sudo apt install -y llvm-14 clang-14 m4 build-essential

# Install dependencies.
sudo apt install -y libelf-dev libconfig-dev libc6-dev-i386 libpcap-dev gcc-multilib 

# You need tools for your kernel since we need BPFTool. If this doesn't work, I'd suggest building BPFTool from source (https://github.com/libbpf/bpftool).
sudo apt install -y linux-tools-$(uname -r)
```
You can use `git` and `make` to build this project. The following should work:

```bash
# Clone repository via Git. Use recursive flag to download LibBPF sub-module.
git clone --recursive https://github.com/aothatday8z8z/xdpnf.git

# Build main project and install as root via Sudo.
cd xdpnf
make && sudo make install
```
## Quick use
`xdpnf` is ready after the build. Here are basic commands (requiring root privileges to execute). For more detail about commands, see [xdpnf tutorial](doc/xdpnf_tutorial.md).

### Enable xdpnf to interface eth0
```bash
sudo xdpnf enable eth0
```
### Disable xdpnf from all interfaces
```bash
sudo xdpnf disable 
``` 
### Create new `test` chain with drop policy
```bash
sudo xdpnf newchain -p drop test
```
### Append new rule into tail chain
Block ipv4 incoming traffic from 10.0.0.5 in `INPUT` chain
```bash
sudo xdpnf append l3_proto=ipv4,saddr=10.0.0.5,action=drop
```
Accept ICMPv6 Echo Reply packets from 2001:db8::2/64
```bash
sudo xdpnf append l3_proto=ipv6,l4_proto=icmpv6,saddr=2001:db8::2/64,icmp_type=129,icmp_code=0,action=accept
```
Block incoming http traffic from ipv4 range 10.0.0.0/24 in user-defined `web_traffic` chain
```bash
sudo xdpnf append -c 'web_traffic' l3_proto=ipv4,l4_proto=tcp,saddr=10.0.0.0/24,dport=80,action=drop
```
Redirect incoming traffic to 10.0.0.0/24 to user-define `vm_traffic` chain
```bash
sudo xdpnf append l3_proto=ipv4,daddr=10.0.0.0/24,goto=vm_traffic
```


