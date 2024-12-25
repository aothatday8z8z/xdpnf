#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>

#include "params.h"
#include "logging.h"
#include "util.h"
#include "stats.h"
#include "xdpnf.h"

#define PROG_NAME "xdpnf"
#define PROG_KERN_NAME "xdpnf_kern"

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

#define PARSE_OK 0
#define PARSE_ERR_INVALID_L3_PROTO      (1<<0)
#define PARSE_ERR_INVALID_L4_PROTO      (1<<1) 
#define PARSE_ERR_INVALID_IP_ADDR       (1<<2)
#define PARSE_ERR_INVALID_PORT          (1<<3)
#define PARSE_ERR_INVALID_TCP_FLAGS     (1<<4)
#define PARSE_ERR_INVALID_ICMP_TYPE     (1<<5)
#define PARSE_ERR_INVALID_ICMP_CODE     (1<<6)
#define PARSE_ERR_INVALID_RATE_LIMIT    (1<<7)

struct flag_val parse_errors[] = {
	{"invalid_l3_proto", PARSE_ERR_INVALID_L3_PROTO},
	{"invalid_l4_proto", PARSE_ERR_INVALID_L4_PROTO},
	{"invalid_ip_addr", PARSE_ERR_INVALID_IP_ADDR},
	{"invalid_port", PARSE_ERR_INVALID_PORT},
	{"invalid_tcp_flags", PARSE_ERR_INVALID_TCP_FLAGS},
	{"invalid_icmp_type", PARSE_ERR_INVALID_ICMP_TYPE},
	{"invalid_icmp_code", PARSE_ERR_INVALID_ICMP_CODE},
	{"invalid_rate_limit", PARSE_ERR_INVALID_RATE_LIMIT},
};


static const struct loadopt {
	bool help;
	struct iface iface;
	enum xdp_attach_mode mode;
} defaults_load = {
	.mode = XDP_MODE_NATIVE,
};


struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {"hw", XDP_MODE_HW},
       {NULL, 0}
};

static struct prog_option load_options[] = {
	DEFINE_OPTION("mode", OPT_ENUM, struct loadopt, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	DEFINE_OPTION("dev", OPT_IFNAME, struct loadopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
	END_OPTIONS
};

int do_load(const void *cfg, const char *pin_root_path)
{
	char errmsg[STRERR_BUFSIZE];
	const struct loadopt *opt = cfg;
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
		pr_warn("xdpnf is already loaded on %s\n", opt->iface.ifname);
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
			goto retry;

		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Couldn't load BPF program: %s(%d)\n", errmsg, err);
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
		pr_info("XDP program loaded on %s\n", opt->iface.ifname);
		// Initialize the default chain
		struct bpf_map_info c_info = {};
		struct chain c;
		struct chain default_chain; 
		c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", &c_info);
		if (c_map_fd < 0) {
			pr_warn("Couldn't find chain map; is xdpnf loaded\n");
			err = EXIT_FAILURE;
			goto out;
		}
	
		err = bpf_map_lookup_elem(c_map_fd, 0, &default_chain);
		if (err) {
			memcpy(default_chain.name, "default", sizeof("default"));
			default_chain.num_rules = 0;
			int key = 0;
			err = bpf_map_update_elem(c_map_fd, &key, &default_chain, BPF_ANY);
			if (err) {
				err = -errno;
				pr_warn("Unable to create default chain: %s\n", strerror(-err));
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

static const struct unloadopt {
	bool all;
	bool keep;
	struct iface iface;
} defaults_unload = {};

static struct prog_option unload_options[] = {
	DEFINE_OPTION("dev", OPT_IFNAME, struct unloadopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .help = "Unload from device <ifname>"),
	DEFINE_OPTION("all", OPT_BOOL, struct unloadopt, all,
		      .short_opt = 'a',
		      .help = "Unload from all interfaces"),
	DEFINE_OPTION("keep-maps", OPT_BOOL, struct unloadopt, keep,
		      .short_opt = 'k',
		      .help = "Don't destroy rule table after unloading"),
	END_OPTIONS
};

int do_unload(const void *cfg, const char *pin_root_path)
{
	const struct unloadopt *opt = cfg;
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
		pr_warn("xdpnf is not loaded on %s\n", opt->iface.ifname);
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
	return err;
}

// Phải chấp nhận mỗi rule chỉ match được một bộ l3, l4 header
// Ví dụ như: IPv4 + TCP, IPv6 + UDP, IPv4 + ICMP, IPv6 + ICMP
// Để match nhiều hơn một bộ l3, l4 header sẽ cần phải tạo nhiều rule
// Ví dụ: drop TCP và UDP ~ drop TCP + drop UDP

/* return 0 if success, otherwise return error code */
static int parse_rule(const char *rule, struct rule *r, struct rate_limiter *rl) {
	int ret = 0;
    memset(r, 0, sizeof(*r));
    char fields[256][256];
    char buffer[1024];
    char *key, *value;

    // Copy the input string to a buffer to avoid modifying the original
    strncpy(buffer, rule, sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0'; // Null-terminate the string

    // Split fields by ','
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

        if (key && value) {
            // Handle special cases like `limit` and `tcp_flags`
            if (strcmp(key, "l3_proto") == 0) {
                if (strcmp(value, "ipv4") == 0) {
                    r->match_field_flags |= MATCH_IPV4; 
                } else if (strcmp(value, "ipv6") == 0) {
                    r->match_field_flags |= MATCH_IPV6;
                } else {
                    ret |= PARSE_ERR_INVALID_L3_PROTO; 
                }
            } 
            else if (strcmp(key, "saddr") == 0) {
                char *cidr = strchr(value, '/');
				int v4prefix = 32; // Default prefix length
				int v6prefix = 128; // Default prefix length
                if (cidr) {
                    *cidr = '\0';
                    if (r->match_field_flags & MATCH_IPV4) {
                        v4prefix = atoi(cidr + 1);
                    } else if (r->match_field_flags & MATCH_IPV6) {
                        v6prefix = atoi(cidr + 1);
                    }
                } 

				if (r->match_field_flags & MATCH_IPV4) {
					if (inet_pton(AF_INET, value, &r->hdr_match.src_ip.ipv4.addr) != 1) {
						ret |= PARSE_ERR_INVALID_IP_ADDR;
					}
					r->hdr_match.src_ip.ipv4.mask = htonl((0xFFFFFFFF << (32 - v4prefix)) & 0xFFFFFFFF);
				} 
				else if (r->match_field_flags & MATCH_IPV6) {
					if (inet_pton(AF_INET6, value, &r->hdr_match.src_ip.ipv6.addr) != 1) {
						ret |= PARSE_ERR_INVALID_IP_ADDR; 
					}
					// Calculate the IPv6 mask
					for (int i = 0; i < 16; i++) {
						if (v6prefix >= 8) {
							r->hdr_match.src_ip.ipv6.mask[i] = 0xFF;
							v6prefix -= 8;
						} else if (v6prefix > 0) {
							r->hdr_match.src_ip.ipv6.mask[i] = (0xFF << (8 - v6prefix)) & 0xFF;
							v6prefix = 0;
						} else {
							r->hdr_match.src_ip.ipv6.mask[i] = 0x00;
						}
					}
				}
			} 
			else if (strcmp(key, "dst_ip") == 0) {
				char *cidr = strchr(value, '/');
				int v4prefix = 32; // Default prefix length
				int v6prefix = 128; // Default prefix length
				if (cidr) {
					*cidr = '\0';
					if (r->match_field_flags & MATCH_IPV4) {
                        v4prefix = atoi(cidr + 1);
                    } else if (r->match_field_flags & MATCH_IPV6) {
                        v6prefix = atoi(cidr + 1);
                    }
				} 

				if (r->match_field_flags & MATCH_IPV4) {
					if (inet_pton(AF_INET, value, &r->hdr_match.dst_ip.ipv4.addr) != 1) {
						ret |= PARSE_ERR_INVALID_IP_ADDR;
					}
					r->hdr_match.dst_ip.ipv4.mask = htonl((0xFFFFFFFF << (32 - v4prefix)) & 0xFFFFFFFF);
				} 
				else if (r->match_field_flags & MATCH_IPV6) {
					if (inet_pton(AF_INET6, value, &r->hdr_match.dst_ip.ipv6.addr) != 1) {
						ret |= PARSE_ERR_INVALID_IP_ADDR; 
					}
					// Calculate the IPv6 mask
					for (int i = 0; i < 16; i++) {
						if (v6prefix >= 8) {
							r->hdr_match.dst_ip.ipv6.mask[i] = 0xFF;
							v6prefix -= 8;
						} else if (v6prefix > 0) {
							r->hdr_match.dst_ip.ipv6.mask[i] = (0xFF << (8 - v6prefix)) & 0xFF;
							v6prefix = 0;
						} else {
							r->hdr_match.dst_ip.ipv6.mask[i] = 0x00;
						}
					}
				}
			}
			else if (strcmp(key, "l4_proto") == 0) {
				if (strcmp(value, "udp") == 0) {
					r->match_field_flags |= MATCH_UDP;
				} else if (strcmp(value, "tcp") == 0) {
					r->match_field_flags |= MATCH_TCP;
				} else if (strcmp(value, "icmp") == 0) {
					r->match_field_flags |= MATCH_ICMP;
				} else if (strcmp(value, "icmpv6") == 0) {
					r->match_field_flags |= MATCH_ICMPV6;
				} else {
					ret |= PARSE_ERR_INVALID_L4_PROTO; 
				}
			} 
			else if (strcmp(key, "sport") == 0) {
				int port = atoi(value);
				if (port < 0 || port > 65535) {
					ret |= PARSE_ERR_INVALID_PORT;
				} else {
					r->match_field_flags |= MATCH_SPORT;
					r->hdr_match.sport = htons((uint16_t)port);
				}
			} 
			else if (strcmp(key, "dport") == 0) {
				int port = atoi(value);
				if (port < 0 || port > 65535) {
					ret |= PARSE_ERR_INVALID_PORT;
				} else {
					r->match_field_flags |= MATCH_DPORT;
					r->hdr_match.dport = htons((uint16_t)port);
				}
			} 
			else if (strcmp(key, "tcp_flags") == 0) {
				char *flag_token = strtok(value, "|");
                bool valid_flags = TRUE;
                while (flag_token) {
                    if (strcmp(flag_token, "syn") == 0) r->hdr_match.tcp_flags |= TCP_FLAG_SYN;
                    else if (strcmp(flag_token, "ack") == 0) r->hdr_match.tcp_flags |= TCP_FLAG_ACK;
                    else if (strcmp(flag_token, "fin") == 0) r->hdr_match.tcp_flags |= TCP_FLAG_FIN;
                    else if (strcmp(flag_token, "urg") == 0) r->hdr_match.tcp_flags |= TCP_FLAG_URG;
                    else if (strcmp(flag_token, "psh") == 0) r->hdr_match.tcp_flags |= TCP_FLAG_PSH;
                    else if (strcmp(flag_token, "rst") == 0) r->hdr_match.tcp_flags |= TCP_FLAG_RST;
                    else if (strcmp(flag_token, "ece") == 0) r->hdr_match.tcp_flags |= TCP_FLAG_ECE;
                    else if (strcmp(flag_token, "cwr") == 0) r->hdr_match.tcp_flags |= TCP_FLAG_CWR;
                    else {
                        valid_flags = FALSE;
                        ret |= PARSE_ERR_INVALID_TCP_FLAGS;
                    }
                    flag_token = strtok(NULL, "|");
                }
                if (valid_flags) {
                    r->match_field_flags |= MATCH_TCP_FLAGS;
                }
			}
			else if (strcmp(key, "icmp_type") == 0) {
				int icmp_type = atoi(value);
				if (icmp_type < 0 || icmp_type > 255) {
					ret |= PARSE_ERR_INVALID_ICMP_TYPE;
				} else {
					r->match_field_flags |= MATCH_ICMP_TYPE;
					r->hdr_match.icmp_type = (uint8_t)icmp_type;
				}
			} 
			else if (strcmp(key, "icmp_code") == 0) {
				int icmp_code = atoi(value);
				if (icmp_code < 0 || icmp_code > 255) {
					ret |= PARSE_ERR_INVALID_ICMP_CODE;
				} 
				else {
					r->match_field_flags |= MATCH_ICMP_CODE;
					r->hdr_match.icmp_code = (uint8_t)icmp_code;
				}
			} 
			else if (strcmp(key, "limit") == 0) {
				char *rate_limit_str = strtok(value, "|");
                char *burst_size_str = strtok(NULL, "|");
                char *limit_type_str = strtok(NULL, "|");

                if (rate_limit_str && burst_size_str && limit_type_str) {
                    rl->rate_limit = atoi(rate_limit_str);
                    rl->max_tokens = atoi(burst_size_str);

					if (rl->rate_limit <= 0 || rl->max_tokens <= 0) {
						ret |= PARSE_ERR_INVALID_RATE_LIMIT;
					}

					if (rl->rate_limit > rl->max_tokens) {
						printf("Rate limit cannot be greater than burst size, set burst size = rate limit\n");
						rl->max_tokens = rl->rate_limit;
					}

                    if (strcmp(limit_type_str, "pps") == 0) {
                        rl->type = LIMIT_PPS;
                    } 
                    else if (strcmp(limit_type_str, "bps") == 0) {
                        rl->type = LIMIT_BPS;
                    }
                    else if (strcmp(limit_type_str, "kbps") == 0) {
                        rl->type = LIMIT_BPS;
                        rl->rate_limit *= 1024;
						rl->max_tokens *= 1024;
                    }
                    else if (strcmp(limit_type_str, "kpps") == 0) {
                        rl->type = LIMIT_PPS;
                        rl->rate_limit *= 1024;
						rl->max_tokens *= 1024;
                    }
                    else {
                        ret |= PARSE_ERR_INVALID_RATE_LIMIT;
                    }

                    r->match_field_flags |= MATCH_RATE_LIMIT;
                } else {
                    ret |= PARSE_ERR_INVALID_RATE_LIMIT;
                }
			}
        } else {
            printf("Invalid field: %s\n", fields[i]);
        }
    }
    return ret;
}

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

struct appendopt {
	char *chain;
	char *rule;
	enum rule_action action;
	char *goto_chain;
} defaults_append = {
	.chain = "default"
};

struct enum_val actions_name_mapping[] = {
	{"drop", RL_DROP},
	{"accept", RL_ACCEPT},
	{"jump", RL_JUMP},
	{NULL, 0}
};

static struct prog_option append_options[] = {
    DEFINE_OPTION("chain", OPT_STRING, struct appendopt, chain,
              .metavar = "<chain_name>",
			  .short_opt = 'c',
			  .required = true,
              .help = "Chain name"),
	DEFINE_OPTION("rule", OPT_STRING, struct appendopt, rule,
		      .metavar = "<rule_string>",
              .required = true,
			  .short_opt = 'r',
		      .help = "Rule string, format: key1=value1,key2=value2,... \n (valid keys: l3_proto, l4_proto, saddr, daddr, sport, dport, tcp_flags, icmp_type, icmp_code, limit)"),
    DEFINE_OPTION("action", OPT_ENUM, struct appendopt, action,
			  .short_opt = 'a',
              .typearg = actions_name_mapping,
              .metavar = "<action>",
              .required = true,
              .help = "Action to perform on packet"),
    DEFINE_OPTION("goto", OPT_STRING, struct appendopt, goto_chain,
              .metavar = "<goto_chain_name>",
			  .short_opt = 'g',
              .help = "Chain name in case of jump action"),
	END_OPTIONS
};

int do_append(__unused const void *cfg, __unused const char *pin_root_path)
{
	int c_map_fd = -1, rl_map_fd = -1, err = EXIT_SUCCESS, lock_fd, c_key, rl_key;
	const struct appendopt *opt = cfg;
    struct chain c = {};
	struct rule r = {.match_field_flags = 0};
	struct timespec now;
	struct rate_limiter rl, tmp_rl;
	struct bpf_map_info c_info = {}, rl_info = {};
	char parse_err[100];

	// Acquire lock
	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	// Get chain map	
	c_map_fd = get_pinned_map_fd(pin_root_path, "chains_map", &c_info);
	if (c_map_fd < 0) {
		pr_warn("Couldn't find chain map; is xdpnf loaded\n");
		err = EXIT_FAILURE;
		goto out;
	}
	err = get_chain_by_name(opt->chain, c_map_fd, &c, &c_key);
	if (err) {
		pr_debug("Couldn't find chain %s\n", opt->chain);
		err = EXIT_FAILURE;
		goto out;
	}
	if (c.num_rules >= MAX_RULES_PER_CHAIN) {
		pr_warn("Chain %s is full\n", opt->chain);
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Found chain %s with id %d\n", opt->chain, c_key);

	// Parse rule
	err = parse_rule(opt->rule, &r, &rl);
	if (err != PARSE_OK) {
		print_flags(parse_err, sizeof(parse_err), parse_errors, err);
		err = EXIT_FAILURE;
		goto out;
	}
	pr_debug("Parsed rule: l3_proto=%s, l4_proto=%s, saddr=%s, daddr=%s, sport=%d, dport=%d, tcp_flags=0x%x, icmp_type=%d, icmp_code=%d\n",
		(r.match_field_flags & MATCH_IPV4) ? "ipv4" : "ipv6",
		(r.match_field_flags & MATCH_TCP) ? "tcp" : (r.match_field_flags & MATCH_UDP) ? "udp" : (r.match_field_flags & MATCH_ICMP) ? "icmp" : "icmpv6",
		(r.match_field_flags & MATCH_IPV4) ? inet_ntoa(*(struct in_addr *)&r.hdr_match.src_ip.ipv4.addr) : inet_ntop(AF_INET6, &r.hdr_match.src_ip.ipv6, parse_err, sizeof(parse_err)),
		(r.match_field_flags & MATCH_IPV4) ? inet_ntoa(*(struct in_addr *)&r.hdr_match.dst_ip.ipv4.addr) : inet_ntop(AF_INET6, &r.hdr_match.dst_ip.ipv6, parse_err, sizeof(parse_err)),
		(r.match_field_flags & MATCH_SPORT) ? ntohs(r.hdr_match.sport) : 0,
		(r.match_field_flags & MATCH_DPORT) ? ntohs(r.hdr_match.dport) : 0,
		(r.match_field_flags & MATCH_TCP_FLAGS) ? r.hdr_match.tcp_flags : 0,
		(r.match_field_flags & MATCH_ICMP_TYPE) ? r.hdr_match.icmp_type : 0,
		(r.match_field_flags & MATCH_ICMP_CODE) ? r.hdr_match.icmp_code : 0);
	
	// Add rate limiter if needed
	if (r.match_field_flags & MATCH_RATE_LIMIT) {
		rl_map_fd = get_pinned_map_fd(pin_root_path, "limiters_map", &rl_info);
		if (rl_map_fd < 0) {
			pr_warn("Couldn't find rate limiter map.\n");
			err = EXIT_FAILURE;
			goto out;
		}
		pr_debug("Found rate limiter map with fd %d for map id %d\n", rl_map_fd, rl_info.id);
		int prev_rl_key = 0;

		// Find the first available rate limiter
		for (rl_key = 0; rl_key < MAX_LIMITERS; rl_key++) {
			err = bpf_map_lookup_elem(rl_map_fd, &rl_key, &tmp_rl);
			if (!err && tmp_rl.enabled == FALSE)
				break;
		}
		if (rl_key == MAX_LIMITERS) {
			pr_warn("Rate limiter map is full\n");
			err = EXIT_FAILURE;
			goto out;
		}
	    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			pr_warn("Couldn't get current time\n");
			err = EXIT_FAILURE;
			goto out;
		}
		rl.enabled = TRUE;
		rl.last_update = now.tv_nsec;
		rl.tokens = 0;
		err = bpf_map_update_elem(rl_map_fd, &rl_key, &rl, BPF_ANY);
		if (err) {
			err = -errno;
			pr_warn("Couldn't add rate limiter to map: %s\n", strerror(-err));
			err = EXIT_FAILURE;
			goto out;
		}
		r.exp_match.limiter_id = rl_key;
	}
	pr_debug("Rate limiter: rate_limit=%" PRIu64 ", max_tokens=%" PRIu64 ", tokens=%" PRIu64 ", type=%d, enabled=%d\n",
		rl.rate_limit, rl.max_tokens, rl.tokens, rl.type, rl.enabled);


	// Handle jump action
	r.rule_action.action = opt->action;
	if (opt->goto_chain) {
		struct chain goto_c;
		int goto_key;
		err = get_chain_by_name(opt->goto_chain, c_map_fd, &goto_c, &goto_key);
		if (err) {
			pr_debug("Jump error, couldn't find destination chain %s.\n", opt->goto_chain);
			err = EXIT_FAILURE;
			goto out;
		}
		else if (goto_key == c_key) {
			pr_warn("Jump error, destination chain is the same as the current chain.\n");
			err = EXIT_FAILURE;
			goto out;
		}
		else if (goto_c.num_rules == 0) {
			pr_warn("Jump error, destination chain is empty.\n");
			err = EXIT_FAILURE;
			goto out;
		}

		r.rule_action.goto_id = goto_key;
		pr_debug("Jumping to chain %s with id %d\n", opt->goto_chain, goto_key);
	}

	// Add rule to chain
	printf("Adding rule to chain %s\n", opt->chain);
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
	prog_lock_release(lock_fd);
	return err;
}

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdpnf COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       load            load xdpnf on an interface\n"
		"       unload          unload xdpnf from an interface\n"
		"       append          append a rule to a chain\n"
		"       delete          delete a rule from a chain\n"
		"       insert          insert a rule to a chain\n"
		"       replace         replace a rule in a chain\n"
		"       list            list all rules in a chain\n"
		"       flush           flush all rules in a chain\n"
		"       new             create a new chain\n"
		"       delete-chain    delete a chain\n"
		"       rename-chain    rename a chain\n"
		"       save            save all rules into a file\n"
		"\n"
		"Use 'xdpnf COMMAND --help' to see options for each command\n");
	return -1;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(load, "Load xdpnf on an interface"),
	DEFINE_COMMAND(unload, "Unload xdpnf from an interface"),
	DEFINE_COMMAND(append, "Append a rule to a chain"),
    // DEFINE_COMMAND(delete, "Delete a rule from a chain"),
    // DEFINE_COMMAND(insert, "Insert a rule to a chain"),
    // DEFINE_COMMAND(replace, "Replace a rule in a chain"),
    // DEFINE_COMMAND(list, "List all rules in a chain"),
    // DEFINE_COMMAND(flush, "Flush all rules in a chain"),
    // DEFINE_COMMAND(new, "Create a new chain"),
    // DEFINE_COMMAND(delete-chain, "Delete a chain"),
    // DEFINE_COMMAND(rename-chain, "Rename a chain"),
    // DEFINE_COMMAND(save, "Save all rules into a file"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct loadopt load;
	struct unloadopt unload;
	struct appendopt append;
	// struct deleteopt delete;
	// struct insertopt insert;
	// struct replaceopt replace;
	// struct listopt list;
	// struct flushopt flush;
	// struct newopt new;
	// struct delete_chainopt delete_chain;
	// struct rename_chainopt rename_chain;
	// struct saveopt save;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, true);

	return do_help(NULL, NULL);
}