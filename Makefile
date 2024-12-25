CC = clang
LLC = llc

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

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
INCS_KERN = -I $(LIBBPFSRC) -I /usr/include -I /usr/local/include -I modules/xdp-tools/headers/ -I $(UTILSDIR)
INCS_USER = -I $(LIBBPFSRC) -I /usr/include -I /usr/local/include  -I $(UTILSDIR)


# Targets
.PHONY: all clean install libs utils xdpnf xdpnf_kern

all: xdpnf xdpnf_kern utils

# User space application
xdpnf: utils libs $(UTIL_OBJECTS)
	mkdir -p $(BUILDDIR)
	$(CC) $(LDFLAGS) $(INCS_USER) -o $(XDPNFOUT) $(LIBBPFOBJS) $(LIBXDPOBJS) $(XDPNFSRC) $(UTIL_OBJECTS)

# XDP kernel program
# Our environment's kernel is small than 5.17, so we can't use bpf_loop helper
# We use O3 to unroll loop then avoid the verifier to fail
xdpnf_kern: $(XDPPROGSRC)
	mkdir -p $(BUILDDIR)
	$(CC) $(INCS_KERN) -D__BPF__ -D__BPF_TRACING__ -Wno-unused-value \
	    -Wno-pointer-sign -Wno-compare-distinct-pointer-types -O3 -emit-llvm -c -g \
	    -o $(BUILDDIR)/xdpnf_kern.ll $<
	$(LLC) -march=bpf -filetype=obj -o $(XDPPROGOBJ) $(BUILDDIR)/xdpnf_kern.ll

# Utils
utils: $(UTIL_OBJECTS)

$(BUILDDIR)/%.o: $(UTILSDIR)/%.c
	mkdir -p $(BUILDDIR)
	$(CC) -O2 -c $(INCS)  -o $@ $<

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
	cp $(XDPPROGOBJ) /etc/xdpnf/
	cp $(XDPNFOUT) /usr/bin/