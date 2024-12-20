#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <bpf_helpers.h>
#include <xdp/xdp_helpers.h>
#include <xdp/prog_dispatcher.h>

#include "xdpfw.h"
#include "xdpfw_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

// Note: liên qua gì đó đến https://github.com/xdp-project/xdp-tools/blob/master/lib/libxdp/protocol.org
struct 
{
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_prog_main);


SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    __u16 pkt_len = data_end - data;
	enum rule_action action = RL_ACCEPT; /* Default action */
	struct hdr_cursor nh;
    struct header_match hdrs;
    struct ethhdr *ethhdr;
	int eth_type;

	nh.pos = data;
	eth_type = parse_ethhdr(&nh, data_end, &ethhdr);
    CHECK_RET(eth_type);

	if (eth_type == bpf_htons(ETH_P_IP)) 
    {
        struct iphdr *iphdr;
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		CHECK_RET(ip_type);
        hdrs.l3_proto == ETH_P_IP;
        hdrs.src_ip.ipv4.addr = iphdr->saddr;
        hdrs.dst_ip.ipv4.addr = iphdr->daddr;
        if (ip_type == IPPROTO_ICMP)
        {
            struct icmphdr_common *icmphdr;
            CHECK_RET(parse_icmphdr_common(&nh, data_end, &icmphdr));
            hdrs.icmp_code = icmphdr->code;
            hdrs.icmp_type = icmphdr->type;
            goto match_rule;
        }
	} 
    else if (eth_type == bpf_htons(ETH_P_IPV6)) 
    {
        struct ipv6hdr *ipv6hdr;
		ip_type = parse_ip6hdr(&nh, data_end, ipv6hdr);
		CHECK_RET(ip_type);
        hdrs.l3_proto == ETH_P_IPV6;
        memcpy(hdrs.src_ip.ipv6.addr, ipv6hdr->saddr, IPV6_ADDR_LEN);
        memcpy(hdrs.dst_ip.ipv6.addr, ipv6hdr->daddr, IPV6_ADDR_LEN);
        if (ip_type == IPPROTO_ICMPV6)
        {
            struct icmphdr_common *icmpv6hdr;
            CHECK_RET(parse_icmphdr_common(&nh, data_end, icmpv6hdr));
            hdrs.icmp_code = icmpv6hdr->code;
            hdrs.icmp_type = icmpv6hdr->type;
            goto match_rule;
        }
            
	} 
    else 
    {
		goto out;
	}

	if (ip_type == IPPROTO_UDP) 
    {
        struct udphdr *udphdr;
		CHECK_RET(parse_udphdr(&nh, data_end, &udphdr));
        hdrs.l4_proto = IPPROTO_UDP;
        hdrs.sport = udphdr->source;
        hdrs.dport = udphdr->dest;
    }
    else if (ip_type == IPPROTO_TCP) 
    {
        struct tcphdr *tcphdr;
        CHECK_RET(parse_tcphdr(&nh, data_end, &tcphdr));
        hdrs.l4_proto = IPPROTO_TCP;
        hdrs.sport = tcphdr->source;
        hdrs.dport = tcphdr->dest;
    }
    else 
    {
        goto out;
    }

match_rule:
    action = process_chain(&pkt_len, &hdrs, 0);
    
out:
    return action;
}

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);