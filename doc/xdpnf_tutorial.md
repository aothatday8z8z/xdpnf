# Table of contents
- [1. Introduction](#1)
	- [1.1. Motivation](#1.1)
	- [1.2. Architecture and Operation](#1.2)
- [2. User guide](#2)
	- [2.1. Commands Overview](#2.1)
	- [2.2. Rule Structure](#2.2)
- [3. Limitations](#3)
- [4. Troubleshooting](#4)

<a name="1"></a>
# 1. Introduction
<a name="1.1"></a>
## 1.1. Motivation
Before starting this project, I had known about eBPF and heard a lot about the ability to customize kernel logic without writing new kernel modules, as well as the impressive packet processing speed of XDP. At that time, I had the idea of implementing a packet scheduling algorithm based on XDP but did not have enough time or motivation to do it. Later, at the company where I work, we faced DDoS attacks targeting customer virtual machines. Our company deploys cloud using OpenStack, and therefore, all traffic to/from virtual machines is handled through Open vSwitch bridges. When a victim virtual machine is attacked, these bridges become bottlenecks, and when they are overloaded, all other virtual machines on the same host as the victim lose connectivity. However, when an interface is attached to a bridge, traffic through that interface no longer goes through the netfilter module. Therefore, it is not possible to use iptables to set rules to prevent attacks, while setting rules on the ovs bridges may cause incompatibility with rules created by OpenStack. We needed an independent tool capable of blocking DDoS traffic before it enters the ovs and with similar features to iptables (since we were already familiar with iptables). And at this point, we thought of eBPF/XDP.

Up to the time I wrote this document, there are a few tools for packet filtering based on XDP:
- [xdp-filter](https://github.com/xdp-project/xdp-tools/tree/master/xdp-filter): This tool aims to demonstrate the impressive packet processing speed of XDP. Therefore, as the author states, "It is deliberately simple and so does not have the same matching capabilities as, e.g., netfilter."
- [xdp-firewall](https://github.com/gamemann/XDP-Firewall): This tool provides more features than xdp-filter, however, its syntax is quite different from iptables and it maintains the rule list through a configuration file, which may cause difficulties for us to get used to it.
- [bpf-iptables](https://github.com/mbertrone/bpf-iptables?tab=readme-ov-file): I found this project after I had already written the main basic features for xdpnf. This project aims to "create a tool based on eBPF/XDP with the highest compatibility with the existing iptables and netfilter system". I have reviewed it, and it lacks some features necessary for us such as rate-limit or creating user-defined chains and jumping from one chain to another, while it has some features that are not really necessary for us such as backward compatibility with iptables. However, I will consider it more carefully in the future to improve xdpnf.

Finally, I concluded that developing a completely new firewall tool based on eBPF/XDP was necessary for our purposes and requirements.
<a name="2"></a>
# 2. User guide
<a name="2.1"></a>
## 2.1. Commands Overview
`xdpnf` provides basic features similar to iptables, however, the command syntax will be slightly different. Run `xdpnf -h` to see all commands. For each command, run `xdpnf <command> -h` to see the options for that command.  
|Command|Example|Meaning|
|---|---|---|
|`enable`|xdpnf enable ens8|enable xdpnf on an interface|
|`disable`|xdpnf disable ens8|disable xdpnf on an interface|
|`append`|xdpnf append l4_proto=ipv4,l3_proto=tcp,saddr=10.0.1.0/24,action=drop|Add a rule to the end of the chain.|
|`delete`|xdpnf delete -i 4 INPUT|Delete a rule from the chain. This can be done in two ways; by entering the entire rule to match (as in the append command example), or by specifying the rule number you want to delete. Rules are numbered from the beginning to the end for each chain, starting with number 1. If the chain is not specified, it will be the INPUT chain.|
|`replace`|xdpnf replace -i 4 -r l4_proto=ipv4,l3_proto=tcp,saddr=10.0.1.0/24,action=drop|Replace the rule with the specified id. It will work similarly to the delete command, but instead of deleting, it will replace it with a new entry.|
|`newchain`|xdpnf newchain -p drop test_chain|Create a new chain with the specified name and default policy (e.g., a chain named test_chain in the example). The name of the new chain must not be the same as an existing chain. The chain's policy can only be: accept (default) or drop.|
|`delchain`|xdpnf delchain test_chain|Delete the chain with the specified name. You must delete all rules of the chain before deleting the chain. If no chain is specified, the INPUT chain will be specified.|
|`rechain`|xdpnf rechain test_old test_new|Rename the chain (e.g., the chain name is changed from test_old to test_new).|
|`list`|xdpnf list test_chain|List all rules in the specified chain. If no chain is specified, it will list all chains.|
|`flush`|xdpnf flush test_chain|Delete all rules in the specified chain. If no chain is specified, the INPUT chain will be specified.|
|`info`|xdpnf info|Print the version and some information about the limitations of xdpnf.|
|`save` (incoming)|xdpnf save -f rules.yaml |Dump rules to a file (similar to iptables-save).|
|`restore` (incoming)|xdpnf restore -f rules.yaml |Restore rules from a file (similar to iptables-restore).|

<a name="2.2"></a>
## 2.2. Rule structure
In `xdpnf`, rules will have a key/value structure as follows: `key1=value1,key2=value2,....`. Keys include two types: **match** and **target**. Match are keys that describe the characteristics of the packet that the rule targets (e.g., IP address, port, protocol, ...). Target are keys that specify the action that the rule will take on the packet if it matches the match. To avoid errors, key/value pairs in the rule should follow the format and order as in the table below (See [command samples](doc/command_sample.txt) for specific rule examples):

|Key|Type|Corresponding Value|Description|Example|
|---|---|---|---------------|---|
|`l3_proto`|match|ipv4, ipv6|Specifies the layer 3 protocol type of the packet that the rule needs to match. If not specified, the rule will match both ipv4 and ipv6.|l3_proto=ipv4|
|`l4_proto`|match|tcp, udp, icmp, icmpv6|Specifies the layer 4 protocol type of the packet that the rule needs to match.|l4_proto=tcp|
|`saddr`|match|IPv4 address in [dot-decimal notation](https://en.wikipedia.org/wiki/Dot-decimal_notation) or IPv6 address [as described in RFC](https://datatracker.ietf.org/doc/html/rfc3513#section-2.2)|Specifies the source IP address of the packet that the rule needs to match. Allows matching a range of addresses when specified in CIDR format. `l3_proto=ipv4` or `l3_proto=ipv6` must be specified before this key.|saddr=10.0.0.56<br>saddr=10.0.0.0/24<br>saddr=2001:db8::1<br>saddr=2001:db8::/32|
|`daddr`|match|IPv4 address in [dot-decimal notation](https://en.wikipedia.org/wiki/Dot-decimal_notation) or IPv6 address [as described in RFC](https://datatracker.ietf.org/doc/html/rfc3513#section-2.2)|Specifies the destination IP address of the packet that the rule needs to match. Allows matching a range of addresses when specified in CIDR format. `l3_proto=ipv4` or `l3_proto=ipv6` must be specified before this key.|daddr=10.0.0.56<br>daddr=10.0.0.0/24<br>daddr=2001:db8::1<br>daddr=2001:db8::/32|
|`sport`|match|Integer in the range [1, 65535]|Specifies the source port of the packet that the rule needs to match. `l4_proto=tcp` or `l4_proto=udp` must be specified before this key.|sport=80|
|`dport`|match|Integer in the range [1, 65535]|Specifies the destination port of the packet that the rule needs to match. `l4_proto=tcp` or `l4_proto=udp` must be specified before this key.|dport=80|
|`icmp_type`|match|Integer in the range [0,255]|Specifies the [type field](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) in the header of the ICMP packet that the rule needs to match. `l4_proto=icmp` or `l4_proto=icmpv6` must be specified before this key.|icmp_type=3<br>icmp_type=8|
|`icmp_code`|match|Integer in the range [0,255]|Specifies the [code field](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) in the header of the ICMP packet that the rule needs to match. `l4_proto=icmp` or `l4_proto=icmpv6` must be specified before this key.|icmp_code=1|
|`tcp_flags`|match|Structure tcp_flags=`flag1`\|`flag2`\|...|Specifies the TCP flags that are set in the packet that the rule needs to match. `l4_proto=tcp` must be specified before this key. Allows matching packets with multiple flags.|tcp_flags=syn<br>tcp_flags=ack\|push|
|`rate_limit`|match|Structure rate_limit=`limit`\|`burst_size`\|`type`|Matches based on the packet arrival rate using a token bucket. The bucket can hold up to `burst_size` tokens, tokens are added to the bucket at a rate of `limit`. When a packet hits the rule, if there are no tokens left in the bucket, the packet matches and the rule applies its action to the packet, otherwise, the packet is considered not to match the rule and consumes a number of tokens in the bucket. `Type` specifies the unit of tokens, currently supports: `pps`, `kpps`, `bps`, `kbps`.|rate_limit=100\|150\|pps<br>rate_limit=100\|150\|kbps|
|`action`|target|drop,accept|Specifies the action to be taken if the packet matches the rule.|action=drop<br>action=accept|
|`goto`|target|name of the next chain|If the packet matches, the rule will forward it to the specified chain for further processing.|goto=new_chain|

<a name="3"></a>
# 3. Limitations
Currently, `xdpnf` has the following limitations:
- Currently, `xdpnf` only supports attaching to XDP hooks, so it can only filter packets in the ingress direction (from the outside network into the system). The opposite direction (packets from the system to the outside) can be implemented based on TC hooks similar to how [bpf-iptables](https://github.com/mbertrone/bpf-iptables?tab=readme-ov-file) does.
- To ensure accurate operation, `xdpnf` should only be attached to a single interface. Attaching to multiple interfaces at once does not cause any errors, but I am not sure if the programs share the same map.
- Currently, `xdpnf` supports a maximum of 32 chains, 100 rules per chain. A packet is allowed to pass through a maximum of 3 chains for goto. This limitation partly comes from the eBPF verifier limiting the complexity of the program, as well as the current design of `xdpnf` (I feel like I am overusing too many for loops and conditional statements when matching packets).  
- Currently, `xdpnf` should be run on systems with kernel version >= 5.15 (see tested systems below). In theory, it can also run on lower kernel versions because I do not use too many new eBPF features (as long as that version supports XDP programs). 

I will try to improve these limitations in the future.  

## Tested systems
| OS | Kernel | Note |
| ---- | ---- | ---- |
| Ubuntu 20.04.6 LTS | 5.4.0-204-generic | 
| Ubuntu 22.04.5 LTS | 5.15.0-127-generic |
| Ubuntu 24.04.1 LTS | 6.8.0-50-generic |

<a name="4"></a>
# 4. Troubleshooting
- When running a command and encountering an error, try running with the `-vv` option to see the specific cause:
	- When enabling and encountering the error "The sequence of 8193 jumps is too complex", try reducing `MAX_RULES_PER_CHAIN` and `MAX_CHAINS` in `src/xdpnf.h` to a lower value. This error comes from the program complexity limitation I mentioned above.