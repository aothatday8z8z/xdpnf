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
#include "xdpnf.h"


// TODO: split into default_chain and sub_chains map
struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CHAINS);
    __type(key, __u32);
    __type(value, struct chain);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} chains_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_LIMITERS);
    __type(key, __u32);
    __type(value, struct rate_limiter);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} limiters_map SEC(".maps");

struct 
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_STATS);
	__type(key, __u32);
	__type(value, struct rule_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");


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

	if (unlikely(eth + 1 > data_end))
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

	if (unlikely(iph + 1 > data_end))
		return -1;

	hdrsize = iph->ihl * 4;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (unlikely(nh->pos + hdrsize > data_end))
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

	if (unlikely(icmp6h + 1 > data_end))
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

	if (unlikely(icmph + 1 > data_end))
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

	if (unlikely(h + 1 > data_end))
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

	if (unlikely(h + 1 > data_end))
		return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (unlikely(len < 0))
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

	if (unlikely(h + 1 > data_end))
		return -1;

	len = h->doff * 4;
	if (unlikely((void *) h + len > data_end))
		return -1;

	nh->pos  = h + 1;
	*tcphdr = h;

	return len;
}


static __always_inline int process_chain(__u16 pkt_len, struct rule *pkt_hdrs, __u32 chain_id) {
    for (int depth = 0; depth < MAX_CHAIN_DEPTH; depth++) {
        struct chain *c= NULL;
		__u16 i;
		c = bpf_map_lookup_elem(&chains_map, &chain_id);
        if (!c)
            return RL_ABORTED;
        for (i = 0; i < MAX_RULES_PER_CHAIN; i++) {
			struct rule *r = &c->rule_list[i];

			__u32 match_field_flags = c->rule_list[i].match_field_flags;

			if (!match_field_flags)
				break;
			
			if ((pkt_hdrs->match_field_flags & match_field_flags & MATCH_PROTOCOL) != (match_field_flags & MATCH_PROTOCOL))
				continue;
			
			// Check IPv4 addr match
			if ((match_field_flags & MATCH_SRC_ADDR) && (match_field_flags & MATCH_IPV4) &&
				((pkt_hdrs->src_ip.ipv4.addr ^ r->src_ip.ipv4.addr) & r->src_ip.ipv4.mask))
				continue;

			if ((match_field_flags & MATCH_DST_ADDR) && (match_field_flags & MATCH_IPV4) &&
				((pkt_hdrs->dst_ip.ipv4.addr ^ r->dst_ip.ipv4.addr) & r->dst_ip.ipv4.mask))
				continue;

			// Check src addr match
			if ((match_field_flags & MATCH_SRC_ADDR) && (match_field_flags & MATCH_IPV6)) {
				__u8 k;
				// bpf_printk("Matching src IPV6 addr\n");
				for (k = 0; k < IPV6_ADDR_LEN; k += 8) {
					if ((((__u64 *)pkt_hdrs->src_ip.ipv6.addr)[k] ^ ((__u64 *)r->src_ip.ipv6.addr)[k]) & ((__u64 *)r->src_ip.ipv6.mask)[k])
						break;
				}
				if (k < IPV6_ADDR_LEN)
					continue;
			}

			if ((match_field_flags & MATCH_DST_ADDR) && (match_field_flags & MATCH_IPV6)) {
				__u8 k;
				// bpf_printk("Matching dst IPV6 addr\n");
				for (k = 0; k < IPV6_ADDR_LEN; k += 8) {
					if ((((__u64 *)pkt_hdrs->dst_ip.ipv6.addr)[k] ^ ((__u64 *)r->dst_ip.ipv6.addr)[k]) & ((__u64 *)r->dst_ip.ipv6.mask)[k])
						break;
				}
				if (k < IPV6_ADDR_LEN)
					continue;
			}

			// Check ICMP match
			if ((match_field_flags & MATCH_ICMP_CODE && pkt_hdrs->icmp_code != r->icmp_code) ||
				(match_field_flags & MATCH_ICMP_TYPE && pkt_hdrs->icmp_type != r->icmp_type) ||
				// Check port match	
				(match_field_flags & MATCH_SPORT && pkt_hdrs->sport != r->sport) ||
				(match_field_flags & MATCH_DPORT && pkt_hdrs->dport != r->dport) ||
				// Check TCP flags match
				(match_field_flags & MATCH_TCP_FLAGS && (pkt_hdrs->tcp_flags & r->tcp_flags) != r->tcp_flags))
				continue;

			// Check rate limit
            if (match_field_flags & MATCH_RATE_LIMIT) {
                struct rate_limiter *rl = NULL;
				rl = bpf_map_lookup_elem(&limiters_map, &r->limiter_id);
                if (!rl) 
					continue;

				__u64 now = 0;
				__s64 delta = 0;
				now = bpf_ktime_get_ns();
				rl->tokens += (now - rl->last_update) * rl->rate_limit; 
				rl->tokens = (rl->tokens > rl->bucket_size) ? (rl->bucket_size) : rl->tokens;
				// bpf_printk("Now: %llu\n", now);
				// bpf_printk("Last update: %llu\n", rl->last_update);
				// bpf_printk("rate: %llu\n", rl->rate_limit);
				// bpf_printk("Current tokens: %llu\n", rl->tokens);
				rl->last_update = now;
				if (rl->type == LIMIT_PPS)
					delta = (__s64)(rl->tokens) - (__s64)(TOKEN_VALUE);
				else if (rl->type == LIMIT_BPS)
				{
					delta = (__s64)(rl->tokens) - (__s64)(pkt_len)*TOKEN_VALUE;
					// bpf_printk("Pkt len: %llu, tokens: %llu, delta: %lld\n", pkt_len, rl->tokens, delta);
				}

				if (delta >= 0) {
					rl->tokens = delta;
					bpf_map_update_elem(&limiters_map, &r->limiter_id, rl, BPF_ANY);
					continue;
				} else {
					bpf_map_update_elem(&limiters_map, &r->limiter_id, rl, BPF_ANY);
				}

            }

			// bpf_printk("Matched rule, do action %d\n", r->action);
			// Update stats
			struct rule_stats *rs = NULL;
			rs = bpf_map_lookup_elem(&stats_map, &r->stats_id);
			if (rs) {
				rs->bytes += pkt_len;
				rs->packets++;
				bpf_map_update_elem(&stats_map, &r->stats_id, rs, BPF_ANY);
			}

            switch (r->action) {
            case RL_ABORTED:
            case RL_DROP:
            case RL_ACCEPT:
            case RL_TX:
            case RL_REDIRECT:
                return r->action;
            case RL_JUMP:
                chain_id = r->goto_id;
                goto next_chain; 
            default:
                break;
            }
        }
        return c->policy;

next_chain:
        continue; 
    }

    return RL_ABORTED;
}
