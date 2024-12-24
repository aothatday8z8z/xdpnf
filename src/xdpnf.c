#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>

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


#define ERR_INVALID_L3_PROTO      (1<<0)
#define ERR_INVALID_L4_PROTO      (1<<1) 
#define ERR_INVALID_IP_ADDR       (1<<2)
#define ERR_INVALID_PORT          (1<<3)
#define ERR_INVALID_TCP_FLAGS     (1<<4)
#define ERR_INVALID_ICMP_TYPE     (1<<5)
#define ERR_INVALID_ICMP_CODE     (1<<6)
#define ERR_INVALID_RATE_LIMIT    (1<<7)


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

out:
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

static int parse_rule(const char *rule, struct rule *r) {
    memset(hm, 0, sizeof(*hm)); // Clear the struct

    char rule_copy[256];
    strncpy(rule_copy, rule, sizeof(rule_copy) - 1);
    rule_copy[sizeof(rule_copy) - 1] = '\0';

    char *token = strtok(rule_copy, ",");
    while (token) {
        char *equals_sign = strchr(token, '=');
        if (equals_sign) {
            *equals_sign = '\0'; 
            const char *key = token;
            const char *value = equals_sign + 1;

            if (strcmp(key, "l3_proto") == 0) {
                if (strcmp(value, "ipv4") == 0) {
                    r->match_field_flags |= MATCH_IPV4; 
                } else if (strcmp(value, "ipv6") == 0) {
                    r->match_field_flags |= MATCH_IPV6;
                } else {
                    return -1; 
                }
            } 
            else if (strcmp(key, "saddr") == 0) {
                char *cidr = strchr(value, '/');
                if (cidr) {
                    *cidr = '\0';
                    int prefix = atoi(cidr + 1); 
                    if (hm->l3_proto == 0) {
                        if (inet_pton(AF_INET, value, &hm->src_ip.ipv4) != 1) {
                            return -1; //
                        }
                        // Chuyển src_ip sang network byte order
                        hm->src_ip.ipv4 = htonl(hm->src_ip.ipv4);
                        hm->src_mask = cidr_to_mask(prefix); // Tính subnet mask
                    } else if (hm->l3_proto == 1) {
                        if (inet_pton(AF_INET6, value, &hm->src_ip.ipv6) != 1) {
                            return PARSE_ERROR_INVALID_IP; // IP không hợp lệ
                        }
                    }
                } 
				else {
                    // Trường hợp không có CIDR
                    if (hm->l3_proto == 0) {
                        if (inet_pton(AF_INET, value, &hm->src_ip.ipv4) != 1) {
                            return PARSE_ERROR_INVALID_IP; // IP không hợp lệ
                        }
                        // Chuyển src_ip sang network byte order
                        hm->src_ip.ipv4 = htonl(hm->src_ip.ipv4);
                    } else if (hm->l3_proto == 1) {
                        if (inet_pton(AF_INET6, value, &hm->src_ip.ipv6) != 1) {
                            return PARSE_ERROR_INVALID_IP; // IP không hợp lệ
                        }
                    }
                }
            } 
			else if (strcmp(key, "dst_ip") == 0) {
                char *cidr = strchr(value, '/');
                if (cidr) {
                    *cidr = '\0'; // Tách CIDR
                    int prefix = atoi(cidr + 1); // Lấy prefix từ CIDR
                    if (hm->l3_proto == 0) {
                        if (inet_pton(AF_INET, value, &hm->dst_ip.ipv4) != 1) {
                            return PARSE_ERROR_INVALID_IP; // IP không hợp lệ
                        }
                        // Chuyển dst_ip sang network byte order
                        hm->dst_ip.ipv4 = htonl(hm->dst_ip.ipv4);
                        hm->dst_mask = cidr_to_mask(prefix); // Tính subnet mask
                    } else if (hm->l3_proto == 1) {
                        if (inet_pton(AF_INET6, value, &hm->dst_ip.ipv6) != 1) {
                            return PARSE_ERROR_INVALID_IP; // IP không hợp lệ
                        }
                    }
                } 
				else {
                    // Trường hợp không có CIDR
                    if (hm->l3_proto == 0) {
                        if (inet_pton(AF_INET, value, &hm->dst_ip.ipv4) != 1) {
                            return PARSE_ERROR_INVALID_IP; // IP không hợp lệ
                        }
                        // Chuyển dst_ip sang network byte order
                        hm->dst_ip.ipv4 = htonl(hm->dst_ip.ipv4);
                    } else if (hm->l3_proto == 1) {
                        if (inet_pton(AF_INET6, value, &hm->dst_ip.ipv6) != 1) {
                            return PARSE_ERROR_INVALID_IP; // IP không hợp lệ
                        }
                    }
                }
			}
  			else if (strcmp(key, "l4_proto") == 0) {
                if (strcmp(value, "udp") == 0) {
                    hm->l4_proto = 0;
                } else if (strcmp(value, "tcp") == 0) {
                    hm->l4_proto = 1;
                } else if (strcmp(value, "icmp") == 0) {
                    hm->l4_proto = 2;
                } else if (strcmp(value, "icmpv6") == 0) {
                    hm->l4_proto = 3;
                } else {
                    return PARSE_ERROR_INVALID_VALUE; // Giá trị không hợp lệ cho l4_proto
                }
            } else if (strcmp(key, "sport") == 0) {
                hm->sport = htons((uint16_t)atoi(value)); // Chuyển port sang network byte order
            } else if (strcmp(key, "dport") == 0) {
                hm->dport = htons((uint16_t)atoi(value)); // Chuyển port sang network byte order
            } else if (strcmp(key, "tcp_flags") == 0) {
                // Xử lý các cờ TCP
                if (strstr(value, "syn")) hm->tcp_flags |= TCP_FLAG_SYN;
                if (strstr(value, "ack")) hm->tcp_flags |= TCP_FLAG_ACK;
                if (strstr(value, "fin")) hm->tcp_flags |= TCP_FLAG_FIN;
                if (strstr(value, "urg")) hm->tcp_flags |= TCP_FLAG_URG;
                if (strstr(value, "psh")) hm->tcp_flags |= TCP_FLAG_PSH;
                if (strstr(value, "rst")) hm->tcp_flags |= TCP_FLAG_RST;
                if (strstr(value, "ece")) hm->tcp_flags |= TCP_FLAG_ECE;
                if (strstr(value, "cwr")) hm->tcp_flags |= TCP_FLAG_CWR;
            } else if (strcmp(key, "icmp_type") == 0) {
                hm->icmp_type = (uint8_t)atoi(value);
            } else if (strcmp(key, "icmp_code") == 0) {
                hm->icmp_code = (uint8_t)atoi(value);
            } else {
                return PARSE_ERROR_INVALID_KEY; // Key không hợp lệ
            }
        } else {
            return PARSE_ERROR_INVALID_KEY; // Key không hợp lệ
        }
        token = strtok(NULL, ",");
    }

    return PARSE_OK; // Thành công
}

static struct prog_option append_options[] = {
    DEFINE_OPTION("chain", OPT_STRING, struct portopt, chain,
              .metavar = "<chain_name>",
              .positional = true,
              .help = "Chain name"),
	DEFINE_OPTION("rule", OPT_STRING, struct portopt, rule,
		      .metavar = "<rule_string>",
              .required = true,
		      .help = "Rule string"),
    DEFINE_OPTION("action", OPT_STRING, struct portopt, action,
              .typearg = actions_name_mapping,
              .metavar = "<action>",
              .required = true,
              .help = "Action to perform on packet"),
    DEFINE_OPTION("goto", OPT_STRING, struct portopt, goto_chain,
              .metavar = "<chain_name>",
              .help = "Chain name in case of jump action"),
	END_OPTIONS
};

int do_append(__unused const void *cfg, __unused const char *pin_root_path)
{
	int map_fd = -1, err = EXIT_SUCCESS, lock_fd;
	const struct portopt *opt = cfg;
    struct chain c;
	struct bpf_map_info info = {};
	__u8 flags = 0;
	__u64 counter;
	__u32 map_key;

	lock_fd = prog_lock_acquire(pin_root_path);
	if (lock_fd < 0)
		return lock_fd;

	map_fd = get_pinned_map_fd(pin_root_path, textify(MAP_NAME_PORTS), &info);
	if (map_fd < 0) {
		pr_warn("Couldn't find port filter map; is xdp-filter loaded "
			"with the right features (udp and/or tcp)?\n");
		err = EXIT_FAILURE;
		goto out;
	}
}

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdpnf COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       load        - load xdpnf on an interface\n"
		"       unload      - unload xdpnf from an interface\n"
        "       append: Append a rule to head of a chain\n"
        "       delete: Delete a rule from a chain\n"
        "       insert: Insert a rule to end of a chain\n"
        "       replace: Replace a rule in a chain\n"
        "       list: List all rules in a chain\n"
        "       flush: Flush all rules in a chain\n"
        "       new: Create a new chain\n"
        "       delete-chain: Delete a chain\n"
        "       rename-chain: Rename a chain\n"
        "       save: save all rules into a file\n"
		"\n"
		"Use 'xdp-filter COMMAND --help' to see options for each command\n");
	return -1;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(load, "Load xdpnf on an interface"),
	DEFINE_COMMAND(unload, "Unload xdpnf from an interface"),
	DEFINE_COMMAND(append, "Append a rule to a chain"),
    DEFINE_COMMAND(delete, "Delete a rule from a chain"),
    DEFINE_COMMAND(insert, "Insert a rule to a chain"),
    DEFINE_COMMAND(replace, "Replace a rule in a chain"),
    DEFINE_COMMAND(list, "List all rules in a chain"),
    DEFINE_COMMAND(flush, "Flush all rules in a chain"),
    DEFINE_COMMAND(new, "Create a new chain"),
    DEFINE_COMMAND(delete-chain, "Delete a chain"),
    DEFINE_COMMAND(rename-chain, "Rename a chain"),
    DEFINE_COMMAND(save, "Save all rules into a file"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

// union all_opts {
// 	struct loadopt load;
// 	struct unloadopt unload;
// 	struct portopt port;
// 	struct ipopt ip;
// 	struct etheropt ether;
// 	struct pollopt poll;
// };

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, true);

	return do_help(NULL, NULL);
}