CC := $(shell which clang-16 || which clang-15 || which clang-14 || which clang-13 || which clang-12 || which clang-11 || which clang)
LLC := $(shell which llc-16 || which llc-15 || which llc-14 || which llc-13 || which llc-12 || which llc-11 || which llc)

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Check clang version
CLANG_VERSION := $(shell echo $(CC) | sed -E 's/[^0-9]*([0-9]+).*/\1/')
ifeq ($(shell [ $(CLANG_VERSION) -lt 11 ] && echo true), true)
$(error Clang version must be 11 or higher. Current version: $(CLANG_VERSION))
endif

# Check llc version
LLC_VERSION := $(shell echo $(LLC) | sed -E 's/[^0-9]*([0-9]+).*/\1/')
ifeq ($(shell [ $(LLC_VERSION) -lt 11 ] && echo true), true)
$(error LLC version must be 11 or higher. Current version: $(LLC_VERSION))
endif

# Main directories
BUILDDIR = build
SRCDIR = src
UTILSDIR = utils
MODULEDIR = modules

# XDP Tools directory
XDPTOOLSDIR = $(MODULEDIR)/xdp-tools
XDPTOOLSHEADERS = $(XDPTOOLSDIR)/headers

# LibXDP and LibBPF directories
LIBXDPDIR = $(XDPTOOLSDIR)/lib/libxdp
LIBBPFDIR = $(XDPTOOLSDIR)/lib/libbpf
LIBBPFSRC = $(LIBBPFDIR)/src

# Source files
UTIL_SOURCES := $(wildcard $(UTILSDIR)/*.c)
UTIL_OBJECTS := $(patsubst $(UTILSDIR)/%.c, $(BUILDDIR)/%.o, $(UTIL_SOURCES))

# XDP program sources
XDPNFSRC = $(SRCDIR)/xdpnf.c
XDPPROGSRC = $(SRCDIR)/xdpnf_kern.c

# XDP program outputs
XDPNFOUT = $(BUILDDIR)/xdpnf
XDPPROGOBJ = $(BUILDDIR)/xdpnf_kern.o

# LibBPF objects
LIBBPFOBJS = $(wildcard $(LIBBPFSRC)/staticobjs/*.o)

# LibXDP objects
LIBXDPOBJS = $(LIBXDPDIR)/sharedobjs/xsk.o $(LIBXDPDIR)/sharedobjs/libxdp.o

# Flags
LDFLAGS += -lconfig -lelf -lz
INCS_KERN = -I $(LIBBPFSRC)
INCS_USER = -I /usr/include -I /usr/local/include -I modules/xdp-tools/lib/libbpf/include/ -I $(UTILSDIR)


# Targets
.PHONY: all clean install libs utils xdpnf xdpnf_kern

all: xdpnf xdpnf_kern utils

# User space application
xdpnf:  libs utils $(UTIL_OBJECTS)
	mkdir -p $(BUILDDIR)
	$(CC) $(LDFLAGS) $(INCS_USER) -o $(XDPNFOUT) $(LIBBPFOBJS) $(LIBXDPOBJS) $(XDPNFSRC) $(UTIL_OBJECTS)

# XDP kernel program
# Our environment's kernel is small than 5.17, so we can't use bpf_loop helper
# We use O3 to unroll loop then avoid the verifier to fail
xdpnf_kern: $(XDPPROGSRC)
	mkdir -p $(BUILDDIR)
	$(CC) $(INCS_KERN) -D__BPF__ -D__BPF_TRACING__ -Wno-unused-value \
	    -Wno-pointer-sign -Wno-compare-distinct-pointer-types -O2 -emit-llvm -c -g \
	    -o $(BUILDDIR)/xdpnf_kern.ll $<
	$(LLC) -march=bpf -filetype=obj -o $(XDPPROGOBJ) $(BUILDDIR)/xdpnf_kern.ll

# Utils
utils: $(UTIL_OBJECTS)

$(BUILDDIR)/%.o: $(UTILSDIR)/%.c
	mkdir -p $(BUILDDIR)
	$(CC) -O2 -c $(INCS_USER)  -o $@ $<

# Libraries
libs:
	$(MAKE) -C $(XDPTOOLSDIR) libxdp
	sudo $(MAKE) -C $(LIBBPFSRC) install
	sudo $(MAKE) -C $(LIBXDPDIR) install

# Clean
clean:
	$(MAKE) -C $(LIBBPFSRC) clean
	$(MAKE) -C $(XDPTOOLSDIR) clean
	rm -rf $(BUILDDIR)

# Install
install: all
	mkdir -p /usr/local/lib/bpf/
	cp $(XDPPROGOBJ) /usr/local/lib/bpf/
	cp $(XDPNFOUT) /usr/bin/
