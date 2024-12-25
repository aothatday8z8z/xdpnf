#pragma once

#include <linux/types.h>

#define MAX_LIMITERS 1000
// #define MAX_CPUS 256
// #define MAX_PCKT_LENGTH 65535
#define RULE_SHIFT 11
#define CHAIN_SHIFT 5
#define MAX_RULES_PER_CHAIN 127
#define MAX_CHAINS 32

// #define CREATE_RULE_ID(chain_id, rule_index) \
//     ((((chain_id) & MAX_CHAINS) << RULE_SHIFT) | ((rule_index) & MAX_RULES_PER_CHAIN))

// #define DECODE_CHAIN_ID(rule_id) \
//     (((rule_id) >> RULE_SHIFT) & MAX_CHAINS)

// #define DECODE_RULE_INDEX(rule_id) \
//     ((rule_id) & MAX_RULES_PER_CHAIN)

#define NANO_TO_SEC 1000000000

#define IPV6_ADDR_LEN 16

#define TRUE 1
#define FALSE 0

#define DEFAULT_BURST_SIZE 1000

// Match fields flags
#define MATCH_IPV4             (1<<0)
#define MATCH_IPV6             (1<<1)
#define MATCH_SRC_ADDR         (1<<2)
#define MATCH_DST_ADDR         (1<<3)

#define MATCH_TCP              (1<<6)
#define MATCH_UDP              (1<<7)
#define MATCH_ICMP             (1<<8)
#define MATCH_ICMPV6           (1<<9)
#define MATCH_SPORT            (1<<10)
#define MATCH_DPORT            (1<<11)
#define MATCH_TCP_FLAGS        (1<<12)
#define MATCH_ICMP_TYPE        (1<<13)
#define MATCH_ICMP_CODE        (1<<14)
#define MATCH_CONNTRACK        (1<<15)
#define MATCH_RATE_LIMIT       (1<<16)
#define MATCH_ALL              0xFFFFFFFF
#define MATCH_PROTOCOL         (MATCH_IPV4|MATCH_IPV6|MATCH_TCP|MATCH_UDP|MATCH_ICMP|MATCH_ICMPV6)
#define MATCH_EXPLICIT         (MATCH_CONNTRACK|MATCH_RATE_LIMIT)

#ifdef __BPF__
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif
#endif

enum limit_type {
    LIMIT_PPS,
    LIMIT_BPS
};

typedef enum {
    ADDR_TYPE_IPV4,
    ADDR_TYPE_IPV6
} address_type;

struct ipv4_addr {
    __be32 addr; 
    __be32 mask;    
};

struct ipv6_addr {
    __u8 addr[IPV6_ADDR_LEN];
    __u8 mask[IPV6_ADDR_LEN];    
};

enum rule_action {
    RL_ABORTED = 0,            // Abort processing
	RL_DROP = 1,             // Drop the packet
	RL_ACCEPT = 2,           // Pass packet out from xdp processing to kernel processing
	RL_TX = 3,               // Send packet to interface which it came from
	RL_REDIRECT = 4,         // Send packet to another interface
    RL_JUMP= 5,              // Jump to another chain
    RL_RETURN = 6            // Return to parent chain or do ACCEPT action if no parent chain
};

struct header_match {
    union {
        struct ipv4_addr ipv4;
        struct ipv6_addr ipv6;
    } src_ip;

    union {
        struct ipv4_addr ipv4;
        struct ipv6_addr ipv6;
    } dst_ip;

    __u32 tcp_flags;
    // __s8 tos;
    __u16 sport;
    __u16 dport;

    __u8 icmp_type;
    __u8 icmp_code;
}__attribute__((__aligned__(8)));


// Rate limiter based on token bucket algorithm
struct rate_limiter {
    __u64 last_update; 
    __u64 rate_limit;
    __u64 max_tokens; // = rate_limit * burst_size        
    __u64 tokens;
    enum limit_type type;
    __u8 enabled;
};

struct explicit_match {
    // TODO: add conntrack match
    __u16 limiter_id; 
}; 

struct action {
    enum rule_action action;
    __u8 goto_id;
};


struct rule
{
    struct header_match hdr_match;
    struct explicit_match exp_match;
    struct action rule_action;
    __u64 hit_count;
    __u32 match_field_flags;
};

struct chain {
    struct rule rule_list[MAX_RULES_PER_CHAIN];
    char name[32];
    __u16 num_rules;
} __attribute__((__aligned__(8)));

