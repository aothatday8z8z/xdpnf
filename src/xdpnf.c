#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <time.h>
#include <ctype.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>

#include "params.h"
#include "logging.h"
#include "util.h"
#include "xdpnf.h"

#define PROG_NAME "xdpnf"
#define PROG_KERN_NAME "xdpnf_kern"


// Error codes for parsing/decode
#define PARSE_OK 0
#define PARSE_ERR_INVALID_L3_PROTO      (1<<0)
#define PARSE_ERR_INVALID_L4_PROTO      (1<<1) 
#define PARSE_ERR_INVALID_IP_ADDR       (1<<2)
#define PARSE_ERR_INVALID_PORT          (1<<3)
#define PARSE_ERR_INVALID_TCP_FLAGS     (1<<4)
#define PARSE_ERR_INVALID_ICMP_TYPE     (1<<5)
#define PARSE_ERR_INVALID_ICMP_CODE     (1<<6)
#define PARSE_ERR_INVALID_RATE_LIMIT    (1<<7)
#define PARSE_ERR_INVALID_ACTION        (1<<8)
#define PARSE_ERR_INVALID_FIELD         (1<<9)

enum {
	TCP_FLAG_CWR = __constant_cpu_to_be32(0x00800000),
	TCP_FLAG_ECE = __constant_cpu_to_be32(0x00400000),
	TCP_FLAG_URG = __constant_cpu_to_be32(0x00200000),
	TCP_FLAG_ACK = __constant_cpu_to_be32(0x00100000),
	TCP_FLAG_PSH = __constant_cpu_to_be32(0x00080000),
	TCP_FLAG_RST = __constant_cpu_to_be32(0x00040000),
	TCP_FLAG_SYN = __constant_cpu_to_be32(0x00020000),
	TCP_FLAG_FIN = __constant_cpu_to_be32(0x00010000),
	TCP_RESERVED_BITS = __constant_cpu_to_be32(0x0F000000),
	TCP_DATA_OFFSET = __constant_cpu_to_be32(0xF0000000)
};

enum rule_keys {
	RULE_KEY_SADDR = 1,
	RULE_KEY_DADDR,
	RULE_KEY_TCP_FLAGS,
	RULE_KEY_SPORT,
	RULE_KEY_DPORT,
	RULE_KEY_ICMP_TYPE,
	RULE_KEY_ICMP_CODE,
	RULE_KEY_L3_PROTO,
	RULE_KEY_L4_PROTO,
	RULE_KEY_RATE_LIMIT,
	RULE_KEY_ACTION,
	RULE_KEY_GOTO_CHAIN,
};

struct enum_val rule_keys[] = {
	{"saddr", RULE_KEY_SADDR},
	{"daddr", RULE_KEY_DADDR},
	{"tcp_flags", RULE_KEY_TCP_FLAGS},
	{"sport", RULE_KEY_SPORT},
	{"dport", RULE_KEY_DPORT},
	{"icmp_type", RULE_KEY_ICMP_TYPE},
	{"icmp_code", RULE_KEY_ICMP_CODE},
	{"l3_proto", RULE_KEY_L3_PROTO},
	{"l4_proto", RULE_KEY_L4_PROTO},
	{"rate_limit", RULE_KEY_RATE_LIMIT},
	{"action", RULE_KEY_ACTION},
	{"goto_chain", RULE_KEY_GOTO_CHAIN},
};

struct flag_val parse_errors[] = {
	{"invalid_l3_proto", PARSE_ERR_INVALID_L3_PROTO},
	{"invalid_l4_proto", PARSE_ERR_INVALID_L4_PROTO},
	{"invalid_ip_addr", PARSE_ERR_INVALID_IP_ADDR},
	{"invalid_port", PARSE_ERR_INVALID_PORT},
	{"invalid_tcp_flags", PARSE_ERR_INVALID_TCP_FLAGS},
	{"invalid_icmp_type", PARSE_ERR_INVALID_ICMP_TYPE},
	{"invalid_icmp_code", PARSE_ERR_INVALID_ICMP_CODE},
	{"invalid_rate_limit", PARSE_ERR_INVALID_RATE_LIMIT},
	{"invalid_action", PARSE_ERR_INVALID_ACTION},
};


static const struct enableopt {
	bool help;
	struct iface iface;
	enum xdp_attach_mode mode;
} defaults_enable = {
	.mode = XDP_MODE_NATIVE,
};


struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {"hw", XDP_MODE_HW},
       {NULL, 0}
};

static struct prog_option enable_options[] = {
	DEFINE_OPTION("mode", OPT_ENUM, struct enableopt, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "enable XDP program in <mode>; default native"),
	DEFINE_OPTION("dev", OPT_IFNAME, struct enableopt, iface,
		      .positional = true,
		      .metavar = "ifname",
		      .required = true,
		      .help = "enable on device <ifname>"),
	END_OPTIONS
};

static int get_chain_by_name(const char *chain_name, int c_map_fd, struct chain *c_ptr, int *c_key) {
	int err = EXIT_FAILURE;
	int key, prev_key;
	FOR_EACH_MAP_KEY(err, c_map_fd, key, prev_key) {
		err = bpf_map_lookup_elem(c_map_fd, &key, c_ptr);
		if (err) {
			continue;
		}
		if (strcmp(c_ptr->name, chain_name) == 0) {
			*c_key = key;
			return EXIT_SUCCESS;
		}
	}
	return err;
}

int do_enable(const void *cfg, const char *pin_root_path)
{
	char errmsg[STRERR_BUFSIZE];
	const struct enableopt *opt = cfg;
	int err = EXIT_SUCCESS, lock_fd;
	struct xdp_program *p = NULL;
	char *filename = NULL;
	int c_map_fd = -1;

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .pin_root_path = pin_root_path);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

	if (opt->mode == XDP_MODE_HW) {
		pr_warn("current xdpnf does not support offloading.\n");
		return EXIT_FAILURE;
	}

	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	err = get_pinned_program(&opt->iface, pin_root_path, NULL, &p);
    
	if (!err) {
		pr_warn("xdpnf is already enabled on %s\n", opt->iface.ifname);
		xdp_program__close(p);
		goto out;
	}

	/* libbpf spits out a lot of unhelpful error messages while loading.
	 * Silence the logging so we can provide our own messages instead; this
	 * is a noop if verbose logging is enabled.
     * Hai note: Không biết có cần thiết không
	 */
	silence_libbpf_logging();

retry:
	xdp_opts.find_filename = "xdpnf_kern.o";
	xdp_opts.opts = &opts;
	/* prog_name is NULL, so choose the first program in object */
	p = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(p);
	if (err) {
		if (err == -EPERM && !double_rlimit())
		{
			goto retry;
		}

		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Couldn't enable BPF program: %s(%d)\n", errmsg, err);
		p = NULL;
		goto out;
	}

	err = attach_xdp_program(p, &opt->iface, opt->mode, pin_root_path);
	if (err) {
		if (err == -EPERM && !double_rlimit()) {
			xdp_program__close(p);
			goto retry;
		}

		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Couldn't attach XDP program on iface '%s': %s(%d)\n",
			opt->iface.ifname, errmsg, err);
		goto out;
	}
	else {
		pr_info("XDP program enabled on %s\n", opt->iface.ifname);
		// Initialize the default chain
		struct chain default_chain = {.policy = RL_ACCEPT}; 
		c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", NULL);
		if (c_map_fd < 0) {
			pr_warn("Couldn't find chain map; is xdpnf enabled\n");
			err = EXIT_FAILURE;
			goto out;
		}

		int key = 0;
		err = get_chain_by_name("INPUT", c_map_fd, &default_chain, &key);
		if (err) {
			pr_debug("Creating INPUT chain\n");
			memcpy(default_chain.name, "INPUT", sizeof("INPUT"));
			default_chain.num_rules = 0;

			err = bpf_map_update_elem(c_map_fd, &key, &default_chain, BPF_ANY);
			if (err) {
				err = -errno;
				pr_warn("Unable to create INPUT chain: %s\n", strerror(-err));
				goto out;
			}
		}
	}

out:
	if (c_map_fd >= 0)
		close(c_map_fd);

	xdp_program__close(p);
	free(filename);
	prog_lock_release(lock_fd);
	if (err)
		pr_warn("Failed to enable xdpnf\n");
	return err;
}

static int remove_unused_maps(const char *pin_root_path)
{
	int dir_fd, err = 0;
    char buf[PATH_MAX];

	dir_fd = open(pin_root_path, O_DIRECTORY);
	if (dir_fd < 0) {
		if (errno == ENOENT)
			return 0;
		err = -errno;
		pr_warn("Unable to open pin directory %s: %s\n",
			pin_root_path, strerror(-err));
		goto out;
	}

    err = unlink_pinned_map(dir_fd, "chains_map");
    if (err)
        goto out;

    err = unlink_pinned_map(dir_fd, "limiters_map");
    if (err)
        goto out;

    err = unlink_pinned_map(dir_fd, "stats_map");
    if (err)
        goto out;

    close(dir_fd);
    dir_fd = -1;

    err = try_snprintf(buf, sizeof(buf), "%s/%s", pin_root_path, "programs");
    if (err)
        goto out;

    pr_debug("Removing program directory %s\n", buf);
    err = rmdir(buf);
    if (err) {
        err = -errno;
        pr_warn("Unable to rmdir: %s\n", strerror(-err));
        goto out;
    }

    pr_debug("Removing pinning directory %s\n", pin_root_path);
    err = rmdir(pin_root_path);
    if (err) {
        err = -errno;
        pr_warn("Unable to rmdir: %s\n", strerror(-err));
        goto out;
    }

out:
	if (dir_fd >= 0)
		close(dir_fd);

	return err;
}

static int remove_iface_program(const struct iface *iface,
				struct xdp_program *prog,
				enum xdp_attach_mode mode, void *arg)
{
	char errmsg[STRERR_BUFSIZE];
	char *pin_root_path = arg;
	int err;

	err = detach_xdp_program(prog, iface, mode, pin_root_path);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Removing XDP program on iface %s failed (%d): %s\n",
			iface->ifname, -err, errmsg);
	}

	return err;
}

static const struct disableopt {
	bool all;
	bool keep;
	struct iface iface;
} defaults_disable = {};

static struct prog_option disable_options[] = {
	DEFINE_OPTION("dev", OPT_IFNAME, struct disableopt, iface,
		      .positional = true,
		      .metavar = "ifname",
		      .help = "disable from device <ifname>"),
	DEFINE_OPTION("all", OPT_BOOL, struct disableopt, all,
		      .short_opt = 'a',
		      .help = "disable from all interfaces"),
	DEFINE_OPTION("keep-maps", OPT_BOOL, struct disableopt, keep,
		      .short_opt = 'k',
		      .help = "Don't destroy rule table after disabling"),
	END_OPTIONS
};

int do_disable(const void *cfg, const char *pin_root_path)
{
	const struct disableopt *opt = cfg;
	int err = EXIT_SUCCESS, lock_fd;
	enum xdp_attach_mode mode;
	struct xdp_program *prog;
	char buf[100];
	__u32 feats;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .pin_root_path = pin_root_path);

	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	if (opt->all) {
		pr_debug("Removing xdpnf from all interfaces\n");
		err = iterate_pinned_programs(pin_root_path,
					      remove_iface_program,
					      (void *)pin_root_path);
		if (err && err != -ENOENT)
			goto out;
		goto clean_maps;
	}

	if (!opt->iface.ifindex) {
		pr_warn("Must specify ifname or --all\n");
		err = EXIT_FAILURE;
		goto out;
	}

	err = get_pinned_program(&opt->iface, pin_root_path, &mode, &prog);
	if (err) {
		pr_warn("xdpnf is not enabled on %s\n", opt->iface.ifname);
		err = EXIT_FAILURE;
		goto out;
	}

	err = remove_iface_program(&opt->iface, prog, mode,
				   (void *)pin_root_path);
	if (err)
		goto out;

clean_maps:
	if (opt->keep) {
		pr_debug("Not removing pinned maps because of --keep-maps option\n");
		goto out;
	}

	pr_debug("Checking map usage and removing unused maps\n");
	err = remove_unused_maps(pin_root_path);
	if (err)
		goto out;

out:
	prog_lock_release(lock_fd);
	if (err)
		pr_warn("Failed to disable xdpnf\n");
	else
		pr_info("XDP program disabled\n");
	return err;
}

// Return 0 if no empty key is found, otherwise return the key
static int get_first_empty_key(int map_fd, int max_elem) {
	int ret = 0;
	for (int i = 1; i <= max_elem; i++) {
		void *tmp;
		if (bpf_map_lookup_elem(map_fd, &i, tmp) && errno == ENOENT) {
			ret = i;
			break;
		}
	}
	return ret;
}

static void empty_rule_init(struct rule *r) {
	__builtin_memset(r, 0, sizeof(struct rule));
	memset(r->src_ip.ipv6.mask, 0xFF, sizeof(r->src_ip.ipv6.mask));
	memset(r->dst_ip.ipv6.mask, 0xFF, sizeof(r->dst_ip.ipv6.mask));
}

// No case-insensitive string comparison
static int strcmpns(const char *str1, const char *str2) {
    while (*str1 && *str2) {
        if (tolower(*str1) != tolower(*str2)) {
            return *str1 - *str2;
        }
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

// Phải chấp nhận mỗi rule chỉ match được một bộ l3, l4 header
// Ví dụ như: IPv4 + TCP, IPv6 + UDP, IPv4 + ICMP, IPv6 + ICMP
// Để match nhiều hơn một bộ l3, l4 header sẽ cần phải tạo nhiều rule
// Ví dụ: drop TCP và UDP ~ drop TCP + drop UDP

/* return 0 if success, otherwise return error code */
static int decode_rule(const char *rule, struct rule *r, struct rate_limiter *rl, char *goto_chain) {
	int ret = 0;
	char fields[256][256];
	char buffer[1024];
	char *key, *value;

	empty_rule_init(r);
	strncpy(buffer, rule, sizeof(buffer));
	buffer[sizeof(buffer) - 1] = '\0'; // Ensure null-terminated

	char *token = strtok(buffer, ",");
	int field_count = 0;

	while (token != NULL && field_count < 256) {
		strncpy(fields[field_count], token, 256);
		fields[field_count][256 - 1] = '\0';
		field_count++;
		token = strtok(NULL, ",");
	}

	// Process each field
	for (int i = 0; i < field_count; i++) {
		key = strtok(fields[i], "=");
		value = strtok(NULL, "=");

		int key_enum = get_enum_value(rule_keys, key);
		switch (key_enum) {
			case RULE_KEY_L3_PROTO:
			{
				if (strcmpns(value, "ipv4") == 0) {
					r->match_field_flags |= MATCH_IPV4; 
				} else if (strcmpns(value, "ipv6") == 0) {
					r->match_field_flags |= MATCH_IPV6;
				} else {
					ret |= PARSE_ERR_INVALID_L3_PROTO; 
				}
				pr_debug("parsed l3_proto\n");
				break;
			}

			case RULE_KEY_SADDR:
			{
				char *cidr = strchr(value, '/');
				int v4prefix = 32; 
				int v6prefix = 128;

				if (r->match_field_flags & MATCH_IPV4) {
					if (cidr) {
						*cidr = '\0';
						v4prefix = atoi(cidr + 1);
					}
					if (inet_pton(AF_INET, value, &r->src_ip.ipv4.addr) != 1) {
						ret |= PARSE_ERR_INVALID_IP_ADDR;
					}
					r->match_field_flags |= MATCH_SRC_ADDR;
					r->src_ip.ipv4.mask = htonl((0xFFFFFFFF << (32 - v4prefix)) & 0xFFFFFFFF);
				}
					
				if (r->match_field_flags & MATCH_IPV6) {
					if (cidr) {
						*cidr = '\0';
						v6prefix = atoi(cidr + 1);
					}
					if (inet_pton(AF_INET6, value, &r->src_ip.ipv6.addr) != 1) {
						ret |= PARSE_ERR_INVALID_IP_ADDR; 
					}
					r->match_field_flags |= MATCH_SRC_ADDR;
					for (int i = 0; i < 16; i++) {
						if (v6prefix >= 8) {
							r->src_ip.ipv6.mask[i] = 0xFF;
							v6prefix -= 8;
						} else if (v6prefix > 0) {
							r->src_ip.ipv6.mask[i] = (0xFF << (8 - v6prefix)) & 0xFF;
							v6prefix = 0;
						} else {
							r->src_ip.ipv6.mask[i] = 0x00;
						}
					}
				}
				pr_debug("pasred saddr %d, mask %d\n", r->src_ip.ipv4.addr, r->src_ip.ipv4.mask);
				break;
			}

			case RULE_KEY_DADDR:
			{
				char *cidr = strchr(value, '/');
				int v4prefix = 32; 
				int v6prefix = 128; 

				if (r->match_field_flags & MATCH_IPV4) {
					if (cidr) {
						*cidr = '\0';
						v4prefix = atoi(cidr + 1);
					}
					if (inet_pton(AF_INET, value, &r->dst_ip.ipv4.addr) != 1) {
						ret |= PARSE_ERR_INVALID_IP_ADDR;
					}
					r->match_field_flags |= MATCH_DST_ADDR;
					r->dst_ip.ipv4.mask = htonl((0xFFFFFFFF << (32 - v4prefix)) & 0xFFFFFFFF);
				} 
				
				if (r->match_field_flags & MATCH_IPV6) {
					if (cidr) {
						*cidr = '\0';
						v6prefix = atoi(cidr + 1);
					}
					if (inet_pton(AF_INET6, value, &r->dst_ip.ipv6.addr) != 1) {
						ret |= PARSE_ERR_INVALID_IP_ADDR; 
					}
					r->match_field_flags |= MATCH_DST_ADDR;
					for (int i = 0; i < 16; i++) {
						if (v6prefix >= 8) {
							r->dst_ip.ipv6.mask[i] = 0xFF;
							v6prefix -= 8;
						} else if (v6prefix > 0) {
							r->dst_ip.ipv6.mask[i] = (0xFF << (8 - v6prefix)) & 0xFF;
							v6prefix = 0;
						} else {
							r->dst_ip.ipv6.mask[i] = 0x00;
						}
					}
				}
				pr_debug("parsed daddr\n");	
				break;
			}

			case RULE_KEY_L4_PROTO:
			{
				if (strcmpns(value, "udp") == 0) {
					r->match_field_flags |= MATCH_UDP;
				} else if (strcmpns(value, "tcp") == 0) {
					r->match_field_flags |= MATCH_TCP;
				} else if (strcmpns(value, "icmp") == 0) {
					r->match_field_flags |= MATCH_ICMP;
				} else if (strcmpns(value, "icmpv6") == 0) {
					r->match_field_flags |= MATCH_ICMPV6;
				} else {
					ret |= PARSE_ERR_INVALID_L4_PROTO; 
				}
				pr_debug("parsed l4_proto\n");
				break;
			}

			case RULE_KEY_SPORT:
			{
				int port = atoi(value);
				if (port < 0 || port > 65535) {
					ret |= PARSE_ERR_INVALID_PORT;
				} else {
					r->match_field_flags |= MATCH_SPORT;
					r->sport = htons((uint16_t)port);
				}
				pr_debug("parsed sport\n");
				break;
			}

			case RULE_KEY_DPORT:
			{
				int port = atoi(value);
				if (port < 0 || port > 65535) {
					ret |= PARSE_ERR_INVALID_PORT;
				} else {
					r->match_field_flags |= MATCH_DPORT;
					r->dport = htons((uint16_t)port);
				}			
				pr_debug("parsed dport\n");
				break;		
			}
			case RULE_KEY_TCP_FLAGS:
			{
				char *flag_token = strtok(value, "|");
				bool valid_flags = TRUE;
				while (flag_token) {
					if (strcmpns(flag_token, "syn") == 0) r->tcp_flags |= TCP_FLAG_SYN;
					else if (strcmpns(flag_token, "ack") == 0) r->tcp_flags |= TCP_FLAG_ACK;
					else if (strcmpns(flag_token, "fin") == 0) r->tcp_flags |= TCP_FLAG_FIN;
					else if (strcmpns(flag_token, "urg") == 0) r->tcp_flags |= TCP_FLAG_URG;
					else if (strcmpns(flag_token, "psh") == 0) r->tcp_flags |= TCP_FLAG_PSH;
					else if (strcmpns(flag_token, "rst") == 0) r->tcp_flags |= TCP_FLAG_RST;
					else if (strcmpns(flag_token, "ece") == 0) r->tcp_flags |= TCP_FLAG_ECE;
					else if (strcmpns(flag_token, "cwr") == 0) r->tcp_flags |= TCP_FLAG_CWR;
					else {
						valid_flags = FALSE;
						ret |= PARSE_ERR_INVALID_TCP_FLAGS;
					}
					flag_token = strtok(NULL, "|");
				}

				if (valid_flags) {
					r->match_field_flags |= MATCH_TCP_FLAGS;
				}
				pr_debug("parsed tcp_flags\n");
				break;
			}

			case RULE_KEY_ICMP_CODE:
			{
				int icmp_code = atoi(value);
				if (icmp_code < 0 || icmp_code > 255) {
					ret |= PARSE_ERR_INVALID_ICMP_CODE;
				} 
				else {
					r->match_field_flags |= MATCH_ICMP_CODE;
					r->icmp_code = (uint8_t)icmp_code;
				}
				pr_debug("parsed icmp_code\n");
				break;
			}

			case RULE_KEY_ICMP_TYPE:
			{
				int icmp_type = atoi(value);
				if (icmp_type < 0 || icmp_type > 255) {
					ret |= PARSE_ERR_INVALID_ICMP_TYPE;
				} else {
					r->match_field_flags |= MATCH_ICMP_TYPE;
					r->icmp_type = (uint8_t)icmp_type;
				}		
				pr_debug("parsed icmp_type\n");
				break;		
			}

			case RULE_KEY_RATE_LIMIT:
			{
				char *rate_limit_str = strtok(value, "|");
				char *burst_size_str = strtok(NULL, "|");
				char *limit_type_str = strtok(NULL, "|");

				if (rate_limit_str && burst_size_str && limit_type_str) {
					rl->rate_limit = atoi(rate_limit_str);
					rl->bucket_size = atoi(burst_size_str);
					// rl->rate_limit *= TOKEN_VALUE;
					rl->bucket_size *= TOKEN_VALUE;

					if (rl->rate_limit <= 0 || rl->bucket_size <= 0) {
						ret |= PARSE_ERR_INVALID_RATE_LIMIT;
					}

					if (rl->rate_limit > rl->bucket_size) {
						pr_warn("Rate limit cannot be greater than burst size, set burst size = rate limit\n");
						rl->bucket_size = rl->rate_limit;
					}

					if (strcmpns(limit_type_str, "pps") == 0) {
						rl->type = LIMIT_PPS;
					} 
					else if (strcmpns(limit_type_str, "bps") == 0) {
						rl->type = LIMIT_BPS;
					}
					else if (strcmpns(limit_type_str, "kbps") == 0) {
						rl->type = LIMIT_BPS;
						rl->rate_limit *= 1024;
						rl->bucket_size *= 1024;
					}
					else if (strcmpns(limit_type_str, "kpps") == 0) {
						rl->type = LIMIT_PPS;
						rl->rate_limit *= 1024;
						rl->bucket_size *= 1024;
					}
					else {
						ret |= PARSE_ERR_INVALID_RATE_LIMIT;
					}

					r->match_field_flags |= MATCH_RATE_LIMIT;
				} else {
					ret |= PARSE_ERR_INVALID_RATE_LIMIT;
				}
				pr_debug("parsed rate_limit\n");
				break;
			}

			case RULE_KEY_ACTION:
			{
				if (strcmpns(value, "drop") == 0) {
					r->action = RL_DROP;
				} else if (strcmpns(value, "accept") == 0) {
					r->action = RL_ACCEPT;
				} else {
					ret |= PARSE_ERR_INVALID_ACTION;
				}
				pr_debug("parsed action\n");
				break;
			}

			case RULE_KEY_GOTO_CHAIN:
			{
				r->action = RL_JUMP;
				strncpy(goto_chain, value, CHAIN_NAME_LEN);
				pr_debug("parsed goto_chain\n");
				break;
			}
			default:
				pr_warn("Invalid field: %s\n", fields[i]);
				ret |= PARSE_ERR_INVALID_FIELD;
		}
	}

	if (r->match_field_flags & MATCH_IPV4 && r->match_field_flags & MATCH_IPV6) {
		pr_warn("Cannot match both IPv4 and IPv6\n");
		ret |= PARSE_ERR_INVALID_L3_PROTO;
	}

	if (r->match_field_flags & MATCH_TCP && r->match_field_flags & MATCH_UDP) {
		pr_warn("Cannot match both TCP and UDP\n");
		ret |= PARSE_ERR_INVALID_L4_PROTO;
	}

	if (r->match_field_flags & MATCH_ICMP && r->match_field_flags & MATCH_ICMPV6) {
		pr_warn("Cannot match both ICMP and ICMPv6\n");
		ret |= PARSE_ERR_INVALID_L4_PROTO;
	}

	if (r->match_field_flags & MATCH_ICMP_CODE && !(r->match_field_flags & MATCH_ICMP)) {
		pr_warn("Cannot match ICMP code without ICMP\n");
		ret |= PARSE_ERR_INVALID_ICMP_CODE;
	}

	if (r->match_field_flags & MATCH_ICMP_TYPE && !(r->match_field_flags & MATCH_ICMP)) {
		pr_warn("Cannot match ICMP type without ICMP\n");
		ret |= PARSE_ERR_INVALID_ICMP_TYPE;
	}

	if ((r->match_field_flags & MATCH_ICMP_CODE) && !(r->match_field_flags & MATCH_ICMP_TYPE)) {
		pr_warn("Cannot match ICMP code without ICMP type\n");
		ret |= PARSE_ERR_INVALID_ICMP_CODE;
	}

	if (r->match_field_flags & MATCH_TCP_FLAGS && !(r->match_field_flags & MATCH_TCP)) {
		pr_warn("Cannot match TCP flags without TCP\n");
		ret |= PARSE_ERR_INVALID_TCP_FLAGS;
	}

	if (r->action != RL_JUMP && r->action != RL_DROP && r->action != RL_ACCEPT) {
		pr_warn("\"action\" must be specificed and is drop, accept or goto\n");
		ret |= PARSE_ERR_INVALID_ACTION;
	}
	return ret;
}

struct appendopt {
	char *chain;
	char *rule;
} defaults_append = {
	.chain = "INPUT"
};


static struct prog_option append_options[] = {
    DEFINE_OPTION("chain", OPT_STRING, struct appendopt, chain,
              .metavar = "<chain_name>",
			  .short_opt = 'c',
              .help = "Chain name. If not specified, append to INPUT chain"),
	DEFINE_OPTION("rule", OPT_STRING, struct appendopt, rule,
		      .metavar = "rule_string",
              .required = true,
			  .positional = true,
		      .help = "Rule string, format: key1=value1,key2=value2,... \n (valid keys: l3_proto, l4_proto, saddr, daddr, sport, dport, tcp_flags, icmp_type, icmp_code, limit, action, goto)"),
	END_OPTIONS
};

int do_append(__unused const void *cfg, __unused const char *pin_root_path)
{
	int c_map_fd = -1, rl_map_fd = -1, st_map_fd = -1, err = EXIT_SUCCESS;
	int lock_fd, c_key, rl_key, st_key;
	const struct appendopt *opt = cfg;
    struct chain c = {};
	struct rule r;
	struct rule_stats st = {.bytes=0, .packets=0};
	struct rate_limiter rl, tmp_rl;
	struct bpf_map_info rl_info = {}, st_info = {};
	char parse_err[100], goto_chain[CHAIN_NAME_LEN];

	// Acquire lock
	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	// Get chain map	
	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", NULL);
	if (c_map_fd < 0) {
		pr_warn("Couldn't find chain map; is xdpnf enabled?\n");
		err = EXIT_FAILURE;
		goto out;
	}
	err = get_chain_by_name(opt->chain, c_map_fd, &c, &c_key);
	if (err) {
		pr_warn("Couldn't find chain %s\n", opt->chain);
		err = EXIT_FAILURE;
		goto out;
	}
	if (c.num_rules == MAX_RULES_PER_CHAIN) {
		pr_warn("Chain %s is full\n", opt->chain);
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Found chain %s with id %d\n", opt->chain, c_key);

	// Parse rule
	err = decode_rule(opt->rule, &r, &rl, goto_chain);
	if (err != PARSE_OK) {
		print_flags(parse_err, sizeof(parse_err), parse_errors, err);
		err = EXIT_FAILURE;
		goto out;
	}
	 
	if (r.action == 0) {
		pr_warn("Action is not specified\n");
		err = EXIT_FAILURE;
		goto out;
	}
	
	// Add rate limiter if needed
	if (r.match_field_flags & MATCH_RATE_LIMIT) {
		rl_map_fd = get_pinned_map_fd(pin_root_path, "limiters_map", &rl_info);
		if (rl_map_fd < 0) {
			pr_warn("Couldn't find rate limiter map.\n");
			err = EXIT_FAILURE;
			goto out;
		}
		pr_debug("Found rate limiter map with fd %d for map id %d\n", rl_map_fd, rl_info.id);

		// Find the first empty rate limiter
		rl_key = get_first_empty_key(rl_map_fd, MAX_LIMITERS);
		if (rl_key == MAX_LIMITERS) {
			pr_warn("Rate limiter map is full\n");
			err = EXIT_FAILURE;
			goto out;
		}

		rl.last_update = 0;
		rl.tokens = rl.bucket_size; // Initialize the bucket with full tokens
		err = bpf_map_update_elem(rl_map_fd, &rl_key, &rl, BPF_ANY);
		if (err) {
			err = -errno;
			pr_warn("Couldn't add rate limiter to map: %s\n", strerror(-err));
			err = EXIT_FAILURE;
			goto out;
		}
		r.limiter_id = rl_key;
	}
	pr_debug("Rate limiter: rate_limit=%llu, bucket_size=%llu, tokens=%llu, type=%d\n",
		rl.rate_limit, rl.bucket_size, rl.tokens, rl.type);


	// Handle jump action
	if (r.action == RL_JUMP) {
		struct chain goto_c;
		int goto_key;
		err = get_chain_by_name(goto_chain, c_map_fd, &goto_c, &goto_key);
		if (err) {
			pr_warn("Jump error, couldn't find destination chain %s.\n", goto_chain);
			err = EXIT_FAILURE;
			goto out;
		}
		else if (goto_key == c_key) {
			pr_warn("Jump error, destination chain is the same as the current chain.\n");
			err = EXIT_FAILURE;
			goto out;
		}

		r.goto_id = goto_key;
		pr_debug("Jumping to chain %s with id %d\n", goto_chain, goto_key);
	}

	// Update rule stats
	st_map_fd = get_pinned_map_fd(pin_root_path, "stats_map", &st_info);
	if (st_map_fd < 0) {
		pr_warn("Couldn't find stats map.\n");
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Found stats map with fd %d for map id %d\n", st_map_fd, st_info.id);
	st_key = get_first_empty_key(st_map_fd, MAX_STATS);
	if (st_key == MAX_STATS) {
		pr_warn("Stats map is full\n");
		err = EXIT_FAILURE;
		goto out;
	}
	err = bpf_map_update_elem(st_map_fd, &st_key, &st, BPF_ANY);
	if (err) {
		err = -errno;
		pr_warn("Couldn't add stats to map: %s\n", strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Added stats with id %d\n", st_key);

	// Add rule to chain
	pr_debug("Adding rule to chain %s\n", opt->chain);
	r.stats_id = st_key;
	c.rule_list[c.num_rules] = r;
	c.num_rules += 1;
	err = bpf_map_update_elem(c_map_fd, &c_key, &c, BPF_ANY);
	if (err) {
		err = -errno;
		pr_warn("Couldn't add rule to chain %s: %s\n", opt->chain, strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}

out:
	if (c_map_fd >= 0)
		close(c_map_fd);
	if (rl_map_fd >= 0)
		close(rl_map_fd);
	if (st_map_fd >= 0)
		close(st_map_fd);
	prog_lock_release(lock_fd);
	if (err == EXIT_SUCCESS) 
		pr_info("Rule appended to chain %s\n", opt->chain);

	return err;
}

struct enum_val policies[] = {
	{"accept", RL_ACCEPT},
	{"drop", RL_DROP},
};

struct newchainopt {
	char *chain;
	enum rule_action policy;
} defaults_newchain = {.policy = RL_ACCEPT};

static struct prog_option newchain_options[] = {
	DEFINE_OPTION("policy", OPT_ENUM, struct newchainopt, policy,
			  .metavar = "<policy>",
			  .short_opt = 'p',
			  .typearg = policies,
			  .help = "Default policy for chain: accept or drop, default is accept"),
	DEFINE_OPTION("chain", OPT_STRING, struct newchainopt, chain,
			  .metavar = "chain_name",
			  .positional = true,
			  .required = true,
			  .help = "Name of new chain"),
	END_OPTIONS
};

int do_newchain(__unused const void *cfg, __unused const char *pin_root_path)
{
	int c_map_fd = -1, err = EXIT_SUCCESS, lock_fd, c_key;
	const struct newchainopt *opt = cfg;
	struct chain c = {};

	// Acquire lock
	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	// Get chain map	
	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", NULL);
	if (c_map_fd < 0) {
		pr_warn("Couldn't find chain map; is xdpnf enabled?\n");
		err = EXIT_FAILURE;
		goto out;
	}
	// Check if chain already exists
	err = get_chain_by_name(opt->chain, c_map_fd, &c, &c_key);
	if (err == EXIT_SUCCESS) {
		pr_warn("Chain %s already exists\n", opt->chain);
		err = EXIT_FAILURE;
		goto out;
	}

	// Find the first available key
	c_key = get_first_empty_key(c_map_fd, MAX_CHAINS);
	if (c_key < 0) {
		pr_warn("Chain map is full with %d elements\n", MAX_CHAINS);
		err = EXIT_FAILURE;
		goto out;
	}

	// Create new chain
	memcpy(c.name, opt->chain, sizeof(c.name));
	c.num_rules = 0;
	c.policy = opt->policy;
	err = bpf_map_update_elem(c_map_fd, &c_key, &c, BPF_ANY);
	if (err) {
		err = -errno;
		pr_warn("Couldn't create chain%s\n", opt->chain);
		pr_debug("Couldn't create chain %s: %s\n", opt->chain, strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}
	pr_info("Created chain %s.", opt->chain);

out:
	if (c_map_fd >= 0)
		close(c_map_fd);
	prog_lock_release(lock_fd);
	return err;
}

struct deleteopt {
	char *chain_name;
	char *rule_str;
	int rule_id;
} defaults_delete = {.chain_name = "INPUT"};

static struct prog_option delete_options[] = {
	DEFINE_OPTION("rule_id", OPT_U32, struct deleteopt, rule_id,
			  .metavar = "<rule_id>",
			  .short_opt = 'i',
			  .help = "Rule id to delete. Only one of rule id or rule string can be specified."),
	DEFINE_OPTION("rule_str", OPT_STRING, struct deleteopt, rule_str,
			  .metavar = "<rule_str>",
			  .short_opt = 'n',
			  .help = "Rule string to delete. Only one of rule id or rule string can be specified."),	
	DEFINE_OPTION("chain", OPT_STRING, struct deleteopt, chain_name,
			  .metavar = "chain_name",
			  .positional = true,
			  .required = true,
			  .help = "Chain name"),
	END_OPTIONS
};

static int rule_compare(struct rule *a, struct rule *b) {
	if (a->match_field_flags != b->match_field_flags) {
		pr_debug("match_field_flags %d %d\n", a->match_field_flags, b->match_field_flags);
		return FALSE;
	}
	if (a->action != b->action) {
		return FALSE;
	}
	if (a->goto_id != b->goto_id) {
		return FALSE;
	}
	if (a->limiter_id != b->limiter_id) {
		return FALSE;
	}
	if (a->match_field_flags & MATCH_IPV4) {
		if (a->src_ip.ipv4.addr != b->src_ip.ipv4.addr) {
			return FALSE;
		}
		if (a->src_ip.ipv4.mask != b->src_ip.ipv4.mask) {
			return FALSE;
		}
		if (a->dst_ip.ipv4.addr != b->dst_ip.ipv4.addr) {
			return FALSE;
		}
		if (a->dst_ip.ipv4.mask != b->dst_ip.ipv4.mask) {
			return FALSE;
		}
	} else if (a->match_field_flags & MATCH_IPV6) {
		if (memcmp(&a->src_ip.ipv6.addr, &b->src_ip.ipv6.addr, sizeof(a->src_ip.ipv6.addr)) != 0) {
			return FALSE;
		}
		if (memcmp(&a->src_ip.ipv6.mask, &b->src_ip.ipv6.mask, sizeof(a->src_ip.ipv6.mask)) != 0) {
			return FALSE;
		}
		if (memcmp(&a->dst_ip.ipv6.addr, &b->dst_ip.ipv6.addr, sizeof(a->dst_ip.ipv6.addr)) != 0) {
			return FALSE;
		}
		if (memcmp(&a->dst_ip.ipv6.mask, &b->dst_ip.ipv6.mask, sizeof(a->dst_ip.ipv6.mask)) != 0) {
			return FALSE;
		}
	}
	if (a->sport != b->sport) {
		return FALSE;
	}
	if (a->dport != b->dport) {
		return FALSE;
	}
	if (a->tcp_flags != b->tcp_flags) {
		return FALSE;
	}
	if (a->icmp_type != b->icmp_type) {
		return FALSE;
	}
	if (a->icmp_code != b->icmp_code) {
		return FALSE;
	}
	return TRUE;
}

int do_delete(__unused const void *cfg, __unused const char *pin_root_path)
{
	int c_map_fd = -1, rl_map_fd = -1, st_map_fd = -1, err = EXIT_SUCCESS, rule_idx = -1; 
	int lock_fd, c_key, rl_key;
	const struct deleteopt *opt = cfg;
	struct chain c = {};
	struct rule r = {};
	struct rate_limiter rl = {};
	struct bpf_map_info rl_info = {};
	char parse_err[100], goto_chain[CHAIN_NAME_LEN];

	// Acquire lock
	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	// Get chain map	
	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", NULL);
	if (c_map_fd < 0) {
		pr_warn("Couldn't find chain map; is xdpnf enabled?\n");
		err = EXIT_FAILURE;
		goto out;
	}
	
	err = get_chain_by_name(opt->chain_name, c_map_fd, &c, &c_key);
	if (err) {
		pr_warn("Couldn't find chain %s\n", opt->chain_name);
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Found chain %s with id %d\n", opt->chain_name, c_key);


	if (!opt->rule_id && !opt->rule_str) {
		pr_warn("Rule id or rule string is required\n");
		err = EXIT_FAILURE;
		goto out;
	}
	if (opt->rule_id && opt->rule_str) {
		pr_warn("Only one of rule id or rule string can be specified\n");
		err = EXIT_FAILURE;
		goto out;
	}

	if (opt->rule_id) {
		if (opt->rule_id < 1 || opt->rule_id > c.num_rules) {
			pr_warn("Rule id %d is out of range\n", opt->rule_id);
			err = EXIT_FAILURE;
			goto out;
		}
		rule_idx = opt->rule_id - 1;
		r = c.rule_list[rule_idx];
	}
	else if (opt->rule_str) {
		err = decode_rule(opt->rule_str, &r, &rl, goto_chain);
		if (err != PARSE_OK) {
			print_flags(parse_err, sizeof(parse_err), parse_errors, err);
			err = EXIT_FAILURE;
			goto out;
		}

		// Find goto chain id if action is jump
		if (r.action == RL_JUMP) {
			struct chain goto_c;
			int goto_key;
			err = get_chain_by_name(goto_chain, c_map_fd, &goto_c, &goto_key);
			if (err) {
				pr_warn("Jump error, couldn't find destination chain %s.\n", goto_chain);
				err = EXIT_FAILURE;
				goto out;
			}
			r.goto_id = goto_key;
		}

		for (int i = 0; i < c.num_rules; i++) {
			if (rule_compare(&r, &c.rule_list[i])) {
				rule_idx = i;
				r = c.rule_list[i];
				break;
			}
		}
		if (rule_idx == -1) {
			pr_warn("Couldn't find rule %s in chain %s\n", opt->rule_str, opt->chain_name);
			err = EXIT_FAILURE;
			goto out;
		}
	}

	// Delete rate limiter if needed
	if (r.match_field_flags & MATCH_RATE_LIMIT) {
		rl_map_fd = get_pinned_map_fd(pin_root_path, "limiters_map", &rl_info);
		if (rl_map_fd < 0) {
			pr_warn("Couldn't find rate limiter map.\n");
			err = EXIT_FAILURE;
			goto out;
		}
		pr_debug("Found rate limiter map with fd %d for map id %d\n", rl_map_fd, rl_info.id);
		rl_key = r.limiter_id;

		err = bpf_map_delete_elem(rl_map_fd, &rl_key);
		if (err) {
			err = -errno;
			pr_warn("Couldn't delete rate limiter from map: %s\n", strerror(-err));
			err = EXIT_FAILURE;
			goto out;
		}
		pr_debug("Deleted rate limiter with id %d\n", rl_key);
	}

	// Delete rule stats
	st_map_fd = get_pinned_map_fd(pin_root_path, "stats_map", NULL);
	err = bpf_map_delete_elem(st_map_fd, &r.stats_id);
	if (err) {
		err = -errno;
		pr_warn("Couldn't delete stats from map: %s\n", strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Deleted stats with id %d\n", r.stats_id);


	// Delete rule from chain
	for (int i=rule_idx; i < c.num_rules; i++) {
			c.rule_list[i] = c.rule_list[i+1];
	}
	c.num_rules -= 1;
	struct rule empty = {.match_field_flags = 0};
	c.rule_list[c.num_rules] = empty;
	err = bpf_map_update_elem(c_map_fd, &c_key, &c, BPF_ANY);
	if (err) {
		err = -errno;
		pr_warn("Couldn't delete rule from chain %s: %s\n", opt->chain_name, strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}
out:
	if (c_map_fd >= 0)
		close(c_map_fd);
	if (rl_map_fd >= 0)
		close(rl_map_fd);
	if (st_map_fd >= 0)
		close(st_map_fd);
	prog_lock_release(lock_fd);
	if (err == EXIT_SUCCESS)
		pr_info("Deleted rule from chain %s\n", opt->chain_name);
	else
		pr_warn("Failed to delete rule from chain %s\n", opt->chain_name);
	return err;
}

struct delchainopt {
	char *chain_name;
} defaults_delchain = {};

static struct prog_option delchain_options[] = {
	DEFINE_OPTION("chain", OPT_STRING, struct delchainopt, chain_name,
			  .metavar = "chain_name",
			  .positional = true,
			  .required = true,
			  .help = "Chain name"),
	END_OPTIONS
};

int do_delchain(__unused const void *cfg, __unused const char *pin_root_path)
{
	int c_map_fd = -1, err = EXIT_SUCCESS, lock_fd, c_key;
	const struct delchainopt *opt = cfg;
	struct chain c = {};

	if (strcmp(opt->chain_name, "INPUT") == 0) {
		pr_warn("Cannot delete INPUT chain\n");
		err = EXIT_FAILURE;
		goto out;
	}

	// Acquire lock
	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	// Get chain map	
	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", NULL);
	if (c_map_fd < 0) {
		pr_debug("Couldn't find chain map; is xdpnf enabled?\n");
		err = EXIT_FAILURE;
		goto out;
	}
	err = get_chain_by_name(opt->chain_name, c_map_fd, &c, &c_key);
	if (err) {
		pr_warn("Couldn't find chain %s\n", opt->chain_name);
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Found chain %s with id %d\n", opt->chain_name, c_key);

	if (c.num_rules > 0) {
		pr_warn("Chain %s is not empty\n", opt->chain_name);
		err = EXIT_FAILURE;
		goto out;
	}

	// Find rules jump to this chain
	int key, prev_key;
	FOR_EACH_MAP_KEY(err, c_map_fd, key, prev_key) {
		err = bpf_map_lookup_elem(c_map_fd, &key, &c);
		if (err) {
			continue;
		}
		for (int i = 0; i < c.num_rules; i++) {
			if (c.rule_list[i].action == RL_JUMP && c.rule_list[i].goto_id == c_key) {
				pr_warn("Rule %d in chain %s jumps to chain %s, please delete it first\n", i+1, c.name, opt->chain_name);
				err = EXIT_FAILURE;
				goto out;
			}
		}
	}

	// Delete chain
	err = bpf_map_delete_elem(c_map_fd, &c_key);
	if (err) {
		err = -errno;
		pr_warn("Couldn't delete chain %s: %s\n", opt->chain_name, strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}

out:
	if (c_map_fd >= 0)
		close(c_map_fd);
	prog_lock_release(lock_fd);
	if (err == EXIT_SUCCESS)
		pr_info("Deleted chain %s\n", opt->chain_name);
	return err;
}

struct rechainopt {
	char *old_chain;
	char *new_chain;
} defaults_rechain = {};

static struct prog_option rechain_options[] = {
	DEFINE_OPTION("old_chain", OPT_STRING, struct rechainopt, old_chain,
			  .metavar = "old_chain_name",
			  .positional = true,
			  .required = true,
			  .help = "Old chain name"),
	DEFINE_OPTION("new_chain", OPT_STRING, struct rechainopt, new_chain,
			  .metavar = "new_chain_name",
			  .positional = true,
			  .required = true,
			  .help = "New chain name"),
	END_OPTIONS
};

int do_rechain(__unused const void *cfg, __unused const char *pin_root_path)
{
	int c_map_fd = -1, err = EXIT_SUCCESS, lock_fd, c_key;
	const struct rechainopt *opt = cfg;
	struct chain c = {};

	// Acquire lock
	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	// Get chain map	
	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", NULL);
	if (c_map_fd < 0) {
		pr_debug("Couldn't find chain map; is xdpnf enabled?\n");
		err = EXIT_FAILURE;
		goto out;
	}
	err = get_chain_by_name(opt->old_chain, c_map_fd, &c, &c_key);
	if (err) {
		pr_warn("Couldn't find chain %s\n", opt->old_chain);
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Found chain %s with id %d\n", opt->old_chain, c_key);

	// Rename chain
	memcpy(c.name, opt->new_chain, sizeof(c.name));
	err = bpf_map_update_elem(c_map_fd, &c_key, &c, BPF_ANY);
	if (err) {
		err = -errno;
		pr_warn("Couldn't rename chain %s to %s: %s\n", opt->old_chain, opt->new_chain, strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}

out:
	if (c_map_fd >= 0)
		close(c_map_fd);
	prog_lock_release(lock_fd);
	if (err == EXIT_SUCCESS)
		pr_info("Renamed chain %s to %s\n", opt->old_chain, opt->new_chain);
	return err;
}

struct flushopt {
	char *chain_name;
} defaults_flush = {.chain_name = "INPUT"};

static struct prog_option flush_options[] = {
	DEFINE_OPTION("chain", OPT_STRING, struct flushopt, chain_name,
			  .metavar = "chain_name",
			  .positional = true,
			  .help = "Chain name, if not specified, INPUT chain will be flushed"),
	END_OPTIONS
};

int do_flush(__unused const void *cfg, __unused const char *pin_root_path)
{
	int c_map_fd = -1, rl_map_fd = -1, st_map_fd = -1, err = EXIT_SUCCESS;
	int lock_fd, c_key, rl_key, st_key;
	const struct flushopt *opt = cfg;
	struct chain c = {};

	// Acquire lock
	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	// Get chain map	
	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", NULL);
	if (c_map_fd < 0) {
		pr_warn("Couldn't find chain map; is xdpnf enabled?\n");
		err = EXIT_FAILURE;
		goto out;
	}

	rl_map_fd = get_pinned_map_fd(pin_root_path, "limiters_map", NULL);
	if (rl_map_fd < 0) {
		pr_warn("Couldn't find rate limiter map.\n");
		err = EXIT_FAILURE;
		goto out;
	}

	st_map_fd = get_pinned_map_fd(pin_root_path, "stats_map", NULL);
	if (st_map_fd < 0) {
		pr_warn("Couldn't find stats map.\n");
		err = EXIT_FAILURE;
		goto out;
	}

	err = get_chain_by_name(opt->chain_name, c_map_fd, &c, &c_key);
	if (err) {
		pr_warn("Couldn't find chain %s\n", opt->chain_name);
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Found chain %s with id %d\n", opt->chain_name, c_key);

	// Delete rate limiters and stats
	for (int i = 0; i < c.num_rules; i++) {
		struct rule r = c.rule_list[i];
		if (r.match_field_flags & MATCH_RATE_LIMIT) {
			rl_key = r.limiter_id;
			err = bpf_map_delete_elem(rl_map_fd, &rl_key);
			if (err) {
				err = -errno;
				pr_warn("Couldn't delete rate limiter from map: %s\n", strerror(-err));
				err = EXIT_FAILURE;
				goto out;
			}
			pr_debug("Deleted rate limiter with id %d\n", rl_key);
		}
		err = bpf_map_delete_elem(st_map_fd, &r.stats_id);
		if (err) {
			err = -errno;
			pr_warn("Couldn't delete stats from map: %s\n", strerror(-err));
			err = EXIT_FAILURE;
			goto out;
		}
		pr_debug("Deleted stats with id %d\n", r.stats_id);
	}

	// Flush chain
	memset(c.rule_list, 0, sizeof(c.rule_list));
	c.num_rules = 0;
	err = bpf_map_update_elem(c_map_fd, &c_key, &c, BPF_ANY);
	if (err) {
		err = -errno;
		pr_warn("Couldn't flush rules in chain %s: %s\n",opt->chain_name, strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}
	pr_info("Flushed chain %s\n", opt->chain_name);

out:
	if (c_map_fd >= 0)
		close(c_map_fd);
	if (rl_map_fd >= 0)
		close(rl_map_fd);
	if (st_map_fd >= 0)
		close(st_map_fd);
	prog_lock_release(lock_fd);
	return err;
}

struct replaceopt {
	char *chain;
	int dest_id;
	char *new_rule;
} defaults_replace = {
	.chain = "INPUT"
};

static struct prog_option replace_options[] = {
	DEFINE_OPTION("dest_id", OPT_U32, struct replaceopt, dest_id,
			  .metavar = "<rule_id>",
			  .short_opt = 'i',
			  .required = true,
			  .help = "Id of rule to replace"),
	DEFINE_OPTION("new_rule", OPT_STRING, struct replaceopt, new_rule,
		      .metavar = "<rule_string>",
			  .required = true,
			  .short_opt = 'r',
		      .help = "Rule string, format: key1=value1,key2=value2,... \n (valid keys: l3_proto, l4_proto, saddr, daddr, sport, dport, tcp_flags, icmp_type, icmp_code, limit, action, goto)"),
	DEFINE_OPTION("chain", OPT_STRING, struct replaceopt, chain,
			  .metavar = "chain_name",
			  .positional = true,
			  .required = true,
			  .help = "Chain name"),	
	END_OPTIONS
};

int do_replace(__unused const void *cfg, __unused const char *pin_root_path)
{
	int c_map_fd = -1, rl_map_fd = -1, st_map_fd = -1, err = EXIT_SUCCESS;
	int lock_fd, c_key, rl_key;
	const struct replaceopt *opt = cfg;
	struct chain c = {};
	struct rule new_r, old_r;
	struct rate_limiter new_rl, old_rl;
	struct rule_stats st = {.bytes=0, .packets=0};
	struct bpf_map_info rl_info = {};
	char parse_err[100], goto_chain[CHAIN_NAME_LEN];

	// Acquire lock
	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	// Get chain map	
	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", NULL);
	if (c_map_fd < 0) {
		pr_warn("Couldn't find chain map; is xdpnf enabled?\n");
		err = EXIT_FAILURE;
		goto out;
	}
	err = get_chain_by_name(opt->chain, c_map_fd, &c, &c_key);
	if (err) {
		pr_warn("Couldn't find chain %s\n", opt->chain);
		err = EXIT_FAILURE;
		goto out;
	}
	if (opt->dest_id < 1 || opt->dest_id > c.num_rules) {
		pr_warn("Rule id %d is out of range\n", opt->dest_id);
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Found chain %s with id %d\n", opt->chain, c_key);
	old_r = c.rule_list[opt->dest_id - 1];

	// Parse new rule
	err = decode_rule(opt->new_rule, &new_r, &new_rl, goto_chain);
	if (err != PARSE_OK) {
		print_flags(parse_err, sizeof(parse_err), parse_errors, err);
		err = EXIT_FAILURE;
		goto out;
	}

	// Handle jump action
	if (new_r.action == RL_JUMP) {
		struct chain goto_c;
		int goto_key;
		err = get_chain_by_name(goto_chain, c_map_fd, &goto_c, &goto_key);
		if (err) {
			pr_warn("Jump error, couldn't find destination chain %s.\n", goto_chain);
			err = EXIT_FAILURE;
			goto out;
		}
		else if (goto_key == c_key) {
			pr_warn("Jump error, destination chain is the same as the current chain.\n");
			err = EXIT_FAILURE;
			goto out;
		}
		new_r.goto_id = goto_key;
	}

	// Handle rate limiter
	if (old_r.match_field_flags & MATCH_RATE_LIMIT) {
		rl_map_fd = get_pinned_map_fd(pin_root_path, "limiters_map", &rl_info);
		if (rl_map_fd < 0) {
			pr_warn("Couldn't find rate limiter map.\n");
			err = EXIT_FAILURE;
			goto out;
		}
		pr_debug("Found rate limiter map with fd %d for map id %d\n", rl_map_fd, rl_info.id);
		rl_key = old_r.limiter_id;

		if (new_r.match_field_flags & MATCH_RATE_LIMIT) {
			// Update rate limiter
			new_rl.tokens = new_rl.bucket_size;
			new_rl.last_update = 0;
			
			err = bpf_map_update_elem(rl_map_fd, &rl_key, &new_rl, BPF_ANY);
			if (err) {
				err = -errno;
				pr_warn("Couldn't update rate limiter in map: %s\n", strerror(-err));
				err = EXIT_FAILURE;
				goto out;
			}
			new_r.limiter_id = rl_key;
			pr_debug("Updated rate limiter with id %d\n", rl_key);
		} else {
			// Delete rate limiter
			err = bpf_map_delete_elem(rl_map_fd, &rl_key);
			if (err) {
				err = -errno;
				pr_warn("Couldn't delete rate limiter from map: %s\n", strerror(-err));
				err = EXIT_FAILURE;
				goto out;
			}
			pr_debug("Deleted rate limiter with id %d\n", rl_key);
		}
	}
	else {
		if (new_r.match_field_flags & MATCH_RATE_LIMIT) {
				// Add rate limiter
				rl_map_fd = get_pinned_map_fd(pin_root_path, "limiters_map", &rl_info);
				if (rl_map_fd < 0) {
					pr_warn("Couldn't find rate limiter map.\n");
					err = EXIT_FAILURE;
					goto out;
				}
				pr_debug("Found rate limiter map with fd %d for map id %d\n", rl_map_fd, rl_info.id);

				// Find the first empty rate limiter
				rl_key = get_first_empty_key(rl_map_fd, MAX_LIMITERS);
				if (rl_key == MAX_LIMITERS) {
					pr_warn("Rate limiter map is full\n");
					err = EXIT_FAILURE;
					goto out;
				}

				new_rl.last_update = 0;
				new_rl.tokens = new_rl.bucket_size;
				err = bpf_map_update_elem(rl_map_fd, &rl_key, &new_rl, BPF_ANY);
				if (err) {
					err = -errno;
					pr_warn("Couldn't add rate limiter to map: %s\n", strerror(-err));
					err = EXIT_FAILURE;
					goto out;
				}
				new_r.limiter_id = rl_key;
				pr_debug("Rate limiter: rate_limit=%llu, bucket_size=%llu, tokens=%llu, type=%d\n",
					new_rl.rate_limit, new_rl.bucket_size, new_rl.tokens, new_rl.type);
			}
	}
	// Update rule stats
	st_map_fd = get_pinned_map_fd(pin_root_path, "stats_map", NULL);
	if (st_map_fd < 0) {
		pr_warn("Couldn't find stats map.\n");
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Found stats map with fd %d\n", st_map_fd);
	err = bpf_map_update_elem(st_map_fd, &old_r.stats_id, &st, BPF_ANY);
	if (err) {
		err = -errno;
		pr_warn("Couldn't update stats in map: %s\n", strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}
	new_r.stats_id = old_r.stats_id;

	// Add rule to chain
	pr_debug("Adding rule to chain %s\n", opt->chain);
	c.rule_list[opt->dest_id-1] = new_r;
	err = bpf_map_update_elem(c_map_fd, &c_key, &c, BPF_ANY);
	if (err) {
		err = -errno;
		pr_warn("Couldn't add rule to chain %s: %s\n", opt->chain, strerror(-err));
		err = EXIT_FAILURE;
		goto out;
	}

out:
	if (c_map_fd >= 0)
		close(c_map_fd);
	if (rl_map_fd >= 0)
		close(rl_map_fd);
	if (st_map_fd >= 0)
		close(st_map_fd);
	if (err == EXIT_SUCCESS)
		pr_info("Rule replaced in chain %s\n", opt->chain);
	else
		pr_warn("Failed to replace rule in chain %s\n", opt->chain);
	prog_lock_release(lock_fd);
	return err;
}

struct listopt {
	char *chain_name;
} defaults_list = {};

static struct prog_option list_options[] = {
	DEFINE_OPTION("chain", OPT_STRING, struct listopt, chain_name,
			  .metavar = "chain_name",
			  .positional = true,
			  .help = "Chain name. If not specified, list all chains"),
	END_OPTIONS
};

static int print_chain(struct chain *c, int c_map_fd, int st_map_fd, int rl_map_fd) {
	switch (c->policy) {
		case RL_ACCEPT:
			printf("Chain %s (policy: accept, %d/%d rules)\n", c->name, c->num_rules, MAX_RULES_PER_CHAIN);
			break;
		case RL_DROP:
			printf("Chain %s (policy: drop, %d/%d rules)\n", c->name, c->num_rules, MAX_RULES_PER_CHAIN);
			break;
		default:
			printf("Chain %s (policy: unknown, %d/%d rules)\n", c->name, c->num_rules, MAX_RULES_PER_CHAIN);
			break;
	}

	printf("%-4s %-7s %-7s %-12s %-12s %-20s %-20s %s\n","id", "pkts", "bytes", "action", "proto", "source", "destination", "details");
	for (int i = 0; i < c->num_rules; i++) {
		struct rule *r = &c->rule_list[i];
		struct rule_stats st;
		int err;
		char src_ip[60] = "anywhere";
		char dst_ip[60] = "anywhere";
		
		char proto[30] = "";
		char detail[100] = "";
		char pkts[10] = "";
		char bytes[10] = "";
		char action[32] = "";
		struct chain goto_c;
		int goto_key;
		struct rate_limiter rl;
		int rl_key;

		// Format hit count
		err = bpf_map_lookup_elem(st_map_fd, &r->stats_id, &st);
		if (err) {
			pr_debug("Couldn't find stats for rule %d\n", i+1);
			continue;
		}

		if (st.packets < KBYTE_TO_BYTE) {
			snprintf(pkts, sizeof(pkts), "%llu", st.packets);
		} else if (st.packets < MBYTE_TO_BYTE) {
			snprintf(pkts, sizeof(pkts), "%.2fK", (double)st.packets/KBYTE_TO_BYTE);
		} else if (st.packets < GBYTE_TO_BYTE) {
			snprintf(pkts, sizeof(pkts), "%.2fM", (double)st.packets/MBYTE_TO_BYTE);
		} else if (st.packets < TBYTE_TO_BYTE) {
			snprintf(pkts, sizeof(pkts), "%.2fG", (double)st.packets/GBYTE_TO_BYTE);
		} else {
			snprintf(pkts, sizeof(pkts), "%.2fT", (double)st.packets/TBYTE_TO_BYTE);
		}

		if (st.bytes < KBYTE_TO_BYTE) {
			snprintf(bytes, sizeof(bytes), "%llu", st.bytes);
		} else if (st.bytes < MBYTE_TO_BYTE) {
			snprintf(bytes, sizeof(bytes), "%.2fK", (double)st.bytes/KBYTE_TO_BYTE);
		} else if (st.bytes < GBYTE_TO_BYTE) {
			snprintf(bytes, sizeof(bytes), "%.2fM", (double)st.bytes/MBYTE_TO_BYTE);
		} else if (st.bytes < TBYTE_TO_BYTE) {
			snprintf(bytes, sizeof(bytes), "%.2fG", (double)st.bytes/GBYTE_TO_BYTE);
		} else {
			snprintf(bytes, sizeof(bytes), "%.2fT", (double)st.bytes/TBYTE_TO_BYTE);
		}

		// Format rule details
		if (r->match_field_flags & MATCH_IPV4) {
			strcat(proto, "ipv4,");
			if (r->match_field_flags & MATCH_SRC_ADDR) {
				char src_ip_mask[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &r->src_ip.ipv4.addr, src_ip, sizeof(src_ip));
				snprintf(src_ip_mask, sizeof(src_ip_mask), "/%d", __builtin_popcount(r->src_ip.ipv4.mask));
				strcat(src_ip, src_ip_mask);
			}
			if (r->match_field_flags & MATCH_DST_ADDR) {
				char dst_ip_mask[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &r->dst_ip.ipv4.addr, dst_ip, sizeof(dst_ip));
				snprintf(dst_ip_mask, sizeof(dst_ip_mask), "/%d", __builtin_popcount(r->dst_ip.ipv4.mask));
				strcat(dst_ip, dst_ip_mask);
			}
		} 
		
		if (r->match_field_flags & MATCH_IPV6) {
			strcat(proto, "ipv6,");
			if (r->match_field_flags & MATCH_SRC_ADDR) {
				char src_ip_mask[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &r->src_ip.ipv6.addr, src_ip, sizeof(src_ip));
				snprintf(src_ip_mask, sizeof(src_ip_mask), "/%d", __builtin_popcountll(*(uint64_t *)&r->src_ip.ipv6.mask[0]) + __builtin_popcountll(*(uint64_t *)&r->src_ip.ipv6.mask[8]));
				strcat(src_ip, src_ip_mask);
			}
			if (r->match_field_flags & MATCH_DST_ADDR) {
				char dst_ip_mask[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &r->dst_ip.ipv6.addr, dst_ip, sizeof(dst_ip));
				snprintf(dst_ip_mask, sizeof(dst_ip_mask), "/%d", __builtin_popcountll(*(uint64_t *)&r->dst_ip.ipv6.mask[0]) + __builtin_popcountll(*(uint64_t *)&r->dst_ip.ipv6.mask[8]));
				strcat(dst_ip, dst_ip_mask);
			}
		}

		if (r->match_field_flags & MATCH_TCP) {
			strcat(proto, "tcp,");
		}
		if (r->match_field_flags & MATCH_UDP) {
			strcat(proto, "udp,");
		}
		if (r->match_field_flags & MATCH_ICMP) {
			strcat(proto, "icmp,");
		}
		if (r->match_field_flags & MATCH_ICMPV6) {
			strcat(proto, "icmpv6,");
		}
		if (proto[strlen(proto) - 1] == ',') {
			proto[strlen(proto) - 1] = '\0';
		} 

		if (r->match_field_flags & MATCH_SPORT) {
			snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail), " sport:%d", ntohs(r->sport));
		}
		if (r->match_field_flags & MATCH_DPORT) {
			snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail), " dport:%d", ntohs(r->dport));
		}
		if (r->match_field_flags & MATCH_TCP_FLAGS) {
			snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail), " tcp_flags:");
			if (r->tcp_flags & TCP_FLAG_SYN) strcat(detail, "SYN,");
			if (r->tcp_flags & TCP_FLAG_ACK) strcat(detail, "ACK,");
			if (r->tcp_flags & TCP_FLAG_FIN) strcat(detail, "FIN,");
			if (r->tcp_flags & TCP_FLAG_URG) strcat(detail, "URG,");
			if (r->tcp_flags & TCP_FLAG_PSH) strcat(detail, "PSH,");
			if (r->tcp_flags & TCP_FLAG_RST) strcat(detail, "RST,");
			if (r->tcp_flags & TCP_FLAG_ECE) strcat(detail, "ECE,");
			if (r->tcp_flags & TCP_FLAG_CWR) strcat(detail, "CWR,");
			if (detail[strlen(detail) - 1] == ',') detail[strlen(detail) - 1] = '\0';
		}
		if (r->match_field_flags & MATCH_ICMP_TYPE) {
			snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail), " icmp_type:%d", r->icmp_type);
		}
		if (r->match_field_flags & MATCH_ICMP_CODE) {
			snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail), " icmp_code:%d", r->icmp_code);
		}
		if (r->match_field_flags & MATCH_RATE_LIMIT) {
			rl_key = r->limiter_id;
			err = bpf_map_lookup_elem(rl_map_fd, &rl_key, &rl);
			if (err) {
				pr_warn("Couldn't find rate limiter with id %d\n", rl_key);
				continue;
			}
			char limit_type[10];
			__u64 limit_value = rl.rate_limit;
			__u64 burst_value = (__u64)(rl.bucket_size/TOKEN_VALUE);
			if (rl.type == LIMIT_PPS) {
				if (limit_value < KBYTE_TO_BYTE) {
					snprintf(limit_type, sizeof(limit_type), "pps");
				} else if (limit_value < MBYTE_TO_BYTE) {
					limit_value /= KBYTE_TO_BYTE;
					burst_value /= KBYTE_TO_BYTE;
					snprintf(limit_type, sizeof(limit_type), "Kpps");
				} else if (limit_value < GBYTE_TO_BYTE) {
					limit_value /= MBYTE_TO_BYTE;
					burst_value /= MBYTE_TO_BYTE;
					snprintf(limit_type, sizeof(limit_type), "Mpps");
				} else {
					limit_value /= GBYTE_TO_BYTE;
					burst_value /= GBYTE_TO_BYTE;
					snprintf(limit_type, sizeof(limit_type), "Gpps");
				}
			} else if (rl.type == LIMIT_BPS) {
				if (limit_value < KBYTE_TO_BYTE) {
					snprintf(limit_type, sizeof(limit_type), "bps");
				} else if (limit_value < MBYTE_TO_BYTE) {
					limit_value /= KBYTE_TO_BYTE;
					burst_value /= KBYTE_TO_BYTE;
					snprintf(limit_type, sizeof(limit_type), "Kbps");
				} else if (limit_value < GBYTE_TO_BYTE) {
					limit_value /= MBYTE_TO_BYTE;
					burst_value /= MBYTE_TO_BYTE;
					snprintf(limit_type, sizeof(limit_type), "Mbps");
				} else {
					limit_value /= GBYTE_TO_BYTE;
					burst_value /= GBYTE_TO_BYTE;
					snprintf(limit_type, sizeof(limit_type), "Gbps");
				}
			}
			snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail), " limit up to %llu %s burst %llu %s", limit_value, limit_type, burst_value, limit_type);
		}

		switch (r->action) {
		case RL_ACCEPT:
			memcpy(action, "ACCEPT", sizeof(action));
			break;
		case RL_DROP:
			memcpy(action, "DROP", sizeof(action));
			break;
		case RL_JUMP:
			goto_key = r->goto_id;
			err = bpf_map_lookup_elem(c_map_fd, &goto_key, &goto_c);
			if (err) {
				memcpy(action, "UNKNOWN", sizeof(action));
			} else {
				memcpy(action, goto_c.name, sizeof(action));
			}
			break;
		default:
			memcpy(action, "UNKNOWN", sizeof(action));
			break;
		}
		printf("%-4d %-7s %-7s %-12s %-12s %-20s %-20s %s\n", i+1, pkts, bytes, action, proto, src_ip, dst_ip, detail);
	}
	printf("\n\n");
	return 0;
}

int do_list(__unused const void *cfg, __unused const char *pin_root_path)
{
	int c_map_fd = -1, st_map_fd = -1, rl_map_fd = -1, err = EXIT_SUCCESS, lock_fd, c_key;
	const struct listopt *opt = cfg;
	struct chain c = {};

	// Acquire lock
	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	// Get chain map	
	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", NULL);
	if (c_map_fd < 0) {
		pr_warn("Couldn't find chain map; is xdpnf enabled?\n");
		err = EXIT_FAILURE;
		goto out;
	}

	st_map_fd = get_pinned_map_fd(pin_root_path, "stats_map", NULL);
	if (st_map_fd < 0) {
		pr_debug("Couldn't find stats map.\n");
		err = EXIT_FAILURE;
		goto out;
	}

	rl_map_fd = get_pinned_map_fd(pin_root_path, "limiters_map", NULL);
	if (rl_map_fd < 0) {
		pr_warn("Couldn't find rate limiter map.\n");
		err = EXIT_FAILURE;
		goto out;
	}

	if (opt->chain_name) {
		err = get_chain_by_name(opt->chain_name, c_map_fd, &c, &c_key);
		if (err) {
			pr_warn("Couldn't find chain %s\n", opt->chain_name);
			err = EXIT_FAILURE;
			goto out;
		}
		print_chain(&c, c_map_fd, st_map_fd, rl_map_fd);
	} else {
		int key, prev_key;
		FOR_EACH_MAP_KEY(err, c_map_fd, key, prev_key) {
			err = bpf_map_lookup_elem(c_map_fd, &key, &c);
			if (err) {
				continue;
			}
			print_chain(&c, c_map_fd, st_map_fd, rl_map_fd);
		}
	}

out: 	
	if (c_map_fd >= 0)
		close(c_map_fd);
	if (st_map_fd >= 0)
		close(st_map_fd);
	prog_lock_release(lock_fd);
	
	return err;
}

// static int encode_rule(struct rule *r, int c_map_fd, int rl_map_fd, char *buf, bool cnt_enabled) 
// {
// 	int ret = 0;
// 	if (cnt_enabled) {
// 		buf += sprintf(buf, "[hit_count=%llu]", r->hit_count);
// 	}
// 	// Handle header match
// 	if (r->match_field_flags & MATCH_IPV4) {
// 		buf += sprintf(buf, "l3_proto=ipv4,");
// 		if (r->match_field_flags & MATCH_SRC_ADDR)
// 			buf += sprintf(buf, "saddr=%s/%d,", inet_ntoa(*(struct in_addr *)&r->src_ip.ipv4.addr),__builtin_popcount(r->src_ip.ipv4.mask));
// 		if (r->match_field_flags & MATCH_DST_ADDR)
// 			buf += sprintf(buf, "daddr=%s/%d,", inet_ntoa(*(struct in_addr *)&r->dst_ip.ipv4.addr),__builtin_popcount(r->src_ip.ipv4.mask));
// 	} else if (r->match_field_flags & MATCH_IPV6) {
// 		buf += sprintf(buf, "l3_proto=ipv6,");
// 		if (r->match_field_flags & MATCH_SRC_ADDR) {
// 			char src_ip[INET6_ADDRSTRLEN];
// 			inet_ntop(AF_INET6, &r->src_ip.ipv6.addr, src_ip, sizeof(src_ip));
// 			buf += sprintf(buf, "saddr=%s/%d,", src_ip, __builtin_popcountll(*(uint64_t *)&r->src_ip.ipv6.mask[0]) + __builtin_popcountll(*(uint64_t *)&r->src_ip.ipv6.mask[8]));
// 		}
// 		if (r->match_field_flags & MATCH_DST_ADDR) {
// 			char dst_ip[INET6_ADDRSTRLEN];
// 			inet_ntop(AF_INET6, &r->dst_ip.ipv6.addr, dst_ip, sizeof(dst_ip));
// 			buf += sprintf(buf, "daddr=%s/%d,", dst_ip, __builtin_popcountll(*(uint64_t *)&r->src_ip.ipv6.mask[0]) + __builtin_popcountll(*(uint64_t *)&r->src_ip.ipv6.mask[8]));
// 		}
// 	}
// 	if (r->match_field_flags & MATCH_TCP) {
// 		buf += sprintf(buf, "l4_proto=tcp,");
// 		if (r->match_field_flags & MATCH_SPORT)
// 			buf += sprintf(buf, "sport=%d,", ntohs(r->sport));
// 		if (r->match_field_flags & MATCH_DPORT)
// 			buf += sprintf(buf, "dport=%d,", ntohs(r->dport));
// 		if (r->match_field_flags & MATCH_TCP_FLAGS) {
// 			char tcp_flags[35];
// 			if (r->tcp_flags & TCP_FLAG_SYN) strcat(tcp_flags, "SYN|");
// 			if (r->tcp_flags & TCP_FLAG_ACK) strcat(tcp_flags, "ACK|");
// 			if (r->tcp_flags & TCP_FLAG_FIN) strcat(tcp_flags, "FIN|");
// 			if (r->tcp_flags & TCP_FLAG_URG) strcat(tcp_flags, "URG|");
// 			if (r->tcp_flags & TCP_FLAG_PSH) strcat(tcp_flags, "PSH|");
// 			if (r->tcp_flags & TCP_FLAG_RST) strcat(tcp_flags, "RST|");
// 			if (r->tcp_flags & TCP_FLAG_ECE) strcat(tcp_flags, "ECE|");
// 			if (r->tcp_flags & TCP_FLAG_CWR) strcat(tcp_flags, "CWR|");
// 			if (tcp_flags[strlen(tcp_flags) - 1] == '|') tcp_flags[strlen(tcp_flags) - 1] = '\0';
// 			buf += sprintf(buf, "tcp_flags=%s,", tcp_flags);
// 		}
// 	}
// 	if (r->match_field_flags & MATCH_UDP) { 
// 		buf += sprintf(buf, "l4_proto=udp,");
// 		if (r->match_field_flags & MATCH_SPORT)
// 			buf += sprintf(buf, "sport=%d,", ntohs(r->sport));
// 		if (r->match_field_flags & MATCH_DPORT)
// 			buf += sprintf(buf, "dport=%d,", ntohs(r->dport));
// 	} 
// 	if (r->match_field_flags & MATCH_ICMP) {
// 		buf += sprintf(buf, "l4_proto=icmp,");
// 		if (r->match_field_flags & MATCH_ICMP_TYPE)
// 			buf += sprintf(buf, "icmp_type=%d,", r->icmp_type);
// 		if (r->match_field_flags & MATCH_ICMP_CODE)
// 			buf += sprintf(buf, "icmp_code=%d,", r->icmp_code);
// 	}
// 	if (r->match_field_flags & MATCH_ICMPV6) {
// 		buf += sprintf(buf, "l4_proto=icmpv6,");
// 		if (r->match_field_flags & MATCH_ICMP_TYPE)
// 			buf += sprintf(buf, "icmp_type=%d,", r->icmp_type);
// 		if (r->match_field_flags & MATCH_ICMP_CODE)
// 			buf += sprintf(buf, "icmp_code=%d,", r->icmp_code);
// 	}
// 	if (r->match_field_flags & MATCH_RATE_LIMIT) {
// 		char limit_type[10];
// 		if (rl->type == LIMIT_PPS) {
// 			strcpy(limit_type, "pps");
// 		} else if (r->limiter.type == LIMIT_BPS) {
// 			strcpy(limit_type, "bps");
// 		} 
// 		buf += sprintf(buf, "limit=%llu|%llu|%s,", rl->rate_limit, rl->bucket_size, limit_type);
// 	}

// 	// Handle rule action
// 	if (r->action == RL_DROP) {
// 		buf += sprintf(buf, "action=drop");
// 	} else if (r->action == RL_ACCEPT) {
// 		buf += sprintf(buf, "action=accept");
// 	} else if (r->action == RL_JUMP) {
// 		int err;
// 		struct chain goto_c;
// 		err = bpf_map_lookup_elem(c_map_fd, &r->goto_id, &goto_c);
// 		buf += sprintf(buf, "goto=%s", goto_chain);
// 	}
// }

// struct saveopt {
// 	char *file;
// 	char *chain_name;
// 	bool counter;
// } defaults_save = {.counter = false};

// static struct prog_option save_options[] = {
// 	DEFINE_OPTION("file", OPT_STRING, struct saveopt, file,
// 			  .metavar = "<file_name>",
// 			  .short_opt = 'f',
// 			  .required = true,
// 			  .help = "File name to save rules"),
// 	DEFINE_OPTION("chain", OPT_STRING, struct saveopt, chain_name,
// 			  .metavar = "<chain_name>",
// 			  .short_opt = 'c',
// 			  .help = "Chain name. If not specified, save all chains"),
// 	DEFINE_OPTION("counter", OPT_BOOL, struct saveopt, counter,
// 			  .short_opt = 'C',
// 			  .help = "Save hit counters"),
// 	END_OPTIONS
// };

// int do_save(__unused const void *cfg, __unused const char *pin_root_path)
// {
// 	int c_map_fd = -1, rl_map_fd = -1, err = EXIT_SUCCESS, lock_fd, c_key;
// 	const struct saveopt *opt = cfg;
// 	time_t rawtime;
// 	struct tm *timeinfo;
// 	struct chain c = {};
// 	struct bpf_map_info c_info = {};
// 	char buf[200];
// 	FILE *fp;

// 	// Acquire lock
// 	lock_fd = prog_lock_acquire(pin_root_path);
// 	if (lock_fd < 0)
// 		return lock_fd;

// 	fp = fopen(opt->file, "w");
// 	if (!fp) {
// 		pr_warn("Couldn't open file %s: %s\n", opt->file, strerror(errno));
// 		err = EXIT_FAILURE;
// 		goto out;
// 	}
// 	time(&rawtime);
// 	timeinfo = localtime(&rawtime);
// 	fprintf(fp, "# xdpnf rules saved on %s \n", asctime(timeinfo));

// 	// Get chain map	
// 	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", &c_info);
// 	if (c_map_fd < 0) {
// 		pr_warn("Couldn't find chain map; is xdpnf enabled?\n");
// 		err = EXIT_FAILURE;
// 		goto out;
// 	}

// 	// Get rate limiter map
// 	rl_map_fd = get_pinned_map_fd(pin_root_path, "limiters_map", &c_info);
// 	if (rl_map_fd < 0) {
// 		pr_warn("Couldn't find rate limiter map; is xdpnf enabled?\n");
// 		err = EXIT_FAILURE;
// 		goto out;
// 	}

// 	if (opt->chain_name) {
// 		err = get_chain_by_name(opt->chain_name, c_map_fd, &c, &c_key);
// 		if (err) {
// 			pr_debug("Couldn't find chain %s\n", opt->chain_name);
// 			err = EXIT_FAILURE;
// 			goto out;
// 		}
// 		fprintf(fp, "*%s (%d rules)\n", c.name, c.num_rules);
// 		for (int i = 0; i < c.num_rules; i++) {
// 			struct rule *r = &c.rule_list[i];
// 			memset(buf, 0, sizeof(buf));
// 			encode_rule(r, buf, c_map_fd, rl_map_fd, opt->counter);
// 			fprintf(fp, "-c %s -r %s\n", c.name, buf);
// 			}
// 		goto out;
// 	}

// 	int key, prev_key;
// 	FOR_EACH_MAP_KEY(err, c_map_fd, key, prev_key) {
// 		err = bpf_map_lookup_elem(c_map_fd, &key, &c);
// 		if (err) {
// 			continue;
// 		}
// 		if (c.num_rules > 0) {
// 			fprintf(fp, "*%s (%d rules)\n", c.name, c.num_rules);
// 			for (int i = 0; i < c.num_rules; i++) {
// 				struct rule *r = &c.rule_list[i];
// 				memset(buf, 0, sizeof(buf));
// 				encode_rule(r, buf, opt->counter);
// 				fprintf(fp, "-c %s -r %s\n", c.name, buf);
// 			}
// 		}
// 	}


// out:
// 	if (c_map_fd >= 0)
// 		close(c_map_fd);
// 	if (fp)
// 		fclose(fp);
// 	prog_lock_release(lock_fd);
// 	return err;
// }
			

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdpnf COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       enable            enable xdpnf on an interface\n"
		"       disable          disable xdpnf from an interface\n"
		"       append          append a rule to a chain\n"
		"       delete          delete a rule from a chain\n"
		// "       insert          insert a rule to a chain\n"
		"       replace         replace a rule in a chain\n"
		"       list            list all rules in a chain\n"
		"       flush           flush all rules in a chain\n"
		"       newchain        create a new chain\n"
		"       delchain        delete a chain\n"
		"       rechain         rename a chain\n"
		"       save            save all rules into a file\n"
		"       restore         restore all rules from a file\n"
		"       info            print xdpnf info\n"
		"\n"
		"Use 'xdpnf COMMAND --help' to see options for each command\n");
	return -1;
}

int do_info(__unused const void *cfg, __unused const char *pin_root_path)
{
	// fprintf(stderr, "xdpnf version: %s\n", XDPNF_VERSION);
	fprintf(stderr, "MAX_CHAINS: %d\n", MAX_CHAINS);
	fprintf(stderr, "MAX_RULES_PER_CHAIN: %d\n", MAX_RULES_PER_CHAIN);
	fprintf(stderr, "MAX_JUMP_DEPTH: %d\n", MAX_JUMP_DEPTH);
	return -1;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(enable, "enable xdpnf on an interface"),
	DEFINE_COMMAND(disable, "disable xdpnf from an interface"),
	DEFINE_COMMAND(append, "Append a rule to a chain"),
    DEFINE_COMMAND(delete, "Delete a rule from a chain"),
    // DEFINE_COMMAND(insert, "Insert a rule to a chain"),
    DEFINE_COMMAND(replace, "Replace a rule in a chain"),
    DEFINE_COMMAND(list, "List all rules in a chain"),
    DEFINE_COMMAND(flush, "Flush all rules in a chain"),
    DEFINE_COMMAND(newchain, "Create a new chain"),
    DEFINE_COMMAND(delchain, "Delete a chain"),
    DEFINE_COMMAND(rechain, "Rename a chain"),
    // DEFINE_COMMAND(save, "Save all rules into a file"),
	// DEFINE_COMMAND(restore, "Restore all rules from a file"),
	{ .name = "info", .func = do_info, .no_cfg = true },
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct enableopt enable;
	struct disableopt disable;
	struct appendopt append;
	struct deleteopt delete;
	// struct insertopt insert;
	struct replaceopt replace;
	struct listopt list;
	struct flushopt flush;
	struct newchainopt newchain;
	struct delchainopt delchain;
	struct rechainopt rechain;
	// struct saveopt save;
	// struct restoreopt restore;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, true);
	return do_help(NULL, NULL);
}