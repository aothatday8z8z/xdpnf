#pragma once

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include "xdpfw.h"


struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_CHAINS);
    __type(key, __u32);
    __type(value, struct chain);
} chains_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_LIMITERS);
    __type(key, __u32);
    __type(value, struct rate_limiter);
} limiters_map SEC(".maps");

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/*
 * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
 * structures.
 */
struct icmphdr_common {
	__u8	type;
	__u8	code;
	__sum16	cksum;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

/* Longest chain of IPv6 extension headers to resolve */
#ifndef IPV6_EXT_MAX_CHAIN
#define IPV6_EXT_MAX_CHAIN 6
#endif

#define MAX_CHAIN_DEPTH 4


#define CHECK_RET(ret)                        \
	do {                                  \
		if ((ret) < 0) {              \
			action = RL_ABORTED; \
			goto out;             \
		}                             \
	} while (0)

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	if (eth + 1 > data_end)
		return -1;

	nh->pos = eth + 1;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline int skip_ip6hdrext(struct hdr_cursor *nh,
					  void *data_end,
					  __u8 next_hdr_type)
{
	for (int i = 0; i < IPV6_EXT_MAX_CHAIN; ++i) {
		struct ipv6_opt_hdr *hdr = nh->pos;

		if (hdr + 1 > data_end)
			return -1;

		switch (next_hdr_type) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_MH:
			nh->pos = (char *)hdr + (hdr->hdrlen + 1) * 8;
			next_hdr_type = hdr->nexthdr;
			break;
		case IPPROTO_AH:
			nh->pos = (char *)hdr + (hdr->hdrlen + 2) * 4;
			next_hdr_type = hdr->nexthdr;
			break;
		case IPPROTO_FRAGMENT:
			nh->pos = (char *)hdr + 8;
			next_hdr_type = hdr->nexthdr;
			break;
		default:
			/* Found a header that is not an IPv6 extension header */
			return next_hdr_type;
		}
	}

	return -1;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (ip6h + 1 > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return skip_ip6hdrext(nh, data_end, ip6h->nexthdr);
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;

	if (icmp6h + 1 > data_end)
		return -1;

	nh->pos   = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;

	if (icmph + 1 > data_end)
		return -1;

	nh->pos  = icmph + 1;
	*icmphdr = icmph;

	return icmph->type;
}

static __always_inline int parse_icmphdr_common(struct hdr_cursor *nh,
						void *data_end,
						struct icmphdr_common **icmphdr)
{
	struct icmphdr_common *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos  = h + 1;
	*icmphdr = h;

	return h->type;
}

/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	if ((void *) h + len > data_end)
		return -1;

	nh->pos  = h + 1;
	*tcphdr = h;

	return len;
}

static __always_inline int is_ipv4_match(__be32 *addr, struct ipv4_addr *match_rule) {
    __be32 masked_ip = *addr & match_rule->mask;
    __be32 masked_rule_addr = match_rule->addr & match_rule->mask;

    return masked_ip == masked_rule_addr;
}

static __always_inline int is_ipv6_match(struct ipv6_addr addr, struct ipv6_addr match_rule) {
    for (int i = 0; i < IPV6_ADDR_LEN; i++) {
        if ((addr.addr[i] & match_rule.mask[i]) != (addr.addr[i] & match_rule.mask[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

static int always_inline rule_match(__u16 *pkt_len, struct header_match *hdrs, struct rule *rule)
{
	if (!rule_hdr_match(hdrs, &rule->hdr_match, rule->match_field_flags))
		return FALSE;
	if (rule->match_field_flags & MATCH_RATE_LIMIT)
	{
			return rule_rate_limit(pkt_len, rule);
	}
}

static __always_inline int rule_rate_limit(__u16 *pkt_len, struct rule *rule)
{
	struct rate_limiter *c = bpf_map_lookup_elem(&limiters_map, &rule->rule_id);
	if (c)
	{
		__u64 now, delta;

		now = bpf_ktime_get_ns();
		c->tokens += (now - c->last_update) * c->rate_limit;
		c->last_update = now;

		if (c->tokens > c->max_tokens)
			c->tokens = c->max_tokens;

		if (rule->exp_match.limit_type == LIMIT_PPS)
			delta = c->tokens - 1;
		else
			delta = c->tokens - *pkt_len;

		if (delta >= 0) {
			c->tokens = delta;
			bpf_map_update_elem(&limiters_map, &rule->rule_id, c, BPF_EXIST);
			return TRUE;
		}
		
		bpf_map_update_elem(&limiters_map, &rule->rule_id, c, BPF_EXIST);
		return FALSE;
	}
	else 
		return FALSE;
}

// Match packet hdr vs rule, return 1 if packet is matched, 0 otherwise
static __always_inline int rule_hdr_match(struct header_match *hdrs, struct header_match *match, __u32 match_field_flags)
{
	int ret = TRUE;

	if (!(match_field_flags & (MATCH_IPV4 | MATCH_IPV6)))
		goto l4_match;

	if (hdrs->l3_proto != match->l3_proto)
		return FALSE;

	if (hdrs->l3_proto == ETH_P_IP)
	{
		if ((match_field_flags & MATCH_SRC_IP_ADDR) && !is_ipv4_match(&(hdrs->src_ip.ipv4.addr), &(match->src_ip.ipv4)))
			return FALSE;

		if ((match_field_flags & MATCH_DST_IP_ADDR) && !is_ipv4_match(&(hdrs->dst_ip.ipv4.addr), &(match->dst_ip.ipv4)))
			return FALSE;
	}

	if (hdrs->l3_proto == ETH_P_IPV6)
	{
		if ((match_field_flags & MATCH_SRC_IP_ADDR) && !is_ipv6_match(hdrs->src_ip.ipv6, match->src_ip.ipv6))
			return FALSE;

		if ((match_field_flags & MATCH_DST_IP_ADDR) && !is_ipv6_match(hdrs->dst_ip.ipv6, match->dst_ip.ipv6))
			return FALSE;
	}

l4_match:
	if (!(match_field_flags & (MATCH_ICMP | MATCH_TCP | MATCH_UDP)))
		goto out;

	if (hdrs->l4_proto != match->l4_proto)
		return FALSE;

	if (hdrs->l4_proto == IPPROTO_ICMP)
	{
		if ((match_field_flags & MATCH_ICMP_CODE) && (hdrs->icmp_code != match->icmp_code))
			return FALSE;

		if ((match_field_flags & MATCH_ICMP_TYPE) && (hdrs->icmp_type != match->icmp_type))
			return FALSE;
	}

	if ((match_field_flags & MATCH_SPORT) && (hdrs->sport != match->sport))
		return FALSE;

	if ((match_field_flags & MATCH_DPORT) && (hdrs->dport != match->dport))
		return FALSE;

	if (hdrs->l4_proto == IPPROTO_TCP) TCP_FLAG_FIN
	{
		if ((match_field_flags & MATCH_TCP_FLAGS) && (hdrs->tcp_flags & match->tcp_flags) != match->tcp_flags)
			return FALSE;
	}

out:
	return ret;
}

static __always_inline int process_chain(__u16 *pkt_len, struct header_match *hdrs, __u32 chain_id) {
    for (int depth = 0; depth < MAX_CHAIN_DEPTH; depth++) {
        struct chain *c = bpf_map_lookup_elem(&chain_maps, &chain_id);
        if (!c)
            return RL_ABORTED;
		
        for (__u32 i = 0; i < c->num_rules; i++) {
			struct rule *r = &c->rule_list[i];
			if (r->match_field_flags == 0)
				break;
				
            if (rule_match(pkt_len, hdrs, r)) {
                switch (r->rule_action.action) {
				case RL_ABORTED:
                case RL_DROP:
                case RL_ACCEPT:
				case RL_TX:
				case RL_REDIRECT:
					return r->rule_action.action;
                case RL_JUMP:
                    chain_id = r->rule_action.chain_id;
                    goto next_chain; 
                default:
                    break;
                }
            }
        }
        return RL_ACCEPT;

next_chain:
        continue; 
    }

    return RL_ABORTED;
}
