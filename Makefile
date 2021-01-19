# Copyright (c) 2015-2021, NVIDIA CORPORATION.
# SPDX-License-Identifier: Apache-2.0

CC=gcc
CFLAGS=-I. -I/opt/ss/include -fPIC -g
# The -lrt flag is needed to avoid a link error related to clock_* methods if glibc < 2.17
LDFLAGS += -ljson-c -lpthread -L/opt/ss/lib64 -lrt -lm

DEPS = base64.h debug.h fault_inj.h ioworker.h json_utils.h \
    json_utils_internal.h pool.h proxyfs.h proxyfs_jsonrpc.h \
    proxyfs_req_resp.h proxyfs_testing.h socket.h time_utils.h

# determine the distribution
uname := $(shell uname)
ifeq ($(uname),Linux)
    linux_distro := $(shell python -c "import platform; print platform.linux_distribution()[0]")
endif

ifeq ($(linux_distro),CentOS Linux)
    LIBINSTALL?=/usr/lib64
else
    LIBINSTALL?=/usr/lib
endif

INCLUDEDIR?=/usr/include

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

all: libproxyfs.so.1.0.0 test

libproxyfs.so.1.0.0: proxyfs_api.o proxyfs_jsonrpc.o proxyfs_req_resp.o json_utils.o base64.o socket.o pool.o ioworker.o time_utils.o fault_inj.o
	$(CC) -shared -fPIC -Wl,-soname,libproxyfs.so.1 -o $@ $+ $(LDFLAGS) -lc
	ln -f -s libproxyfs.so.1.0.0 ./libproxyfs.so.1
	ln -f -s libproxyfs.so.1.0.0 ./libproxyfs.so


test: proxyfs_api.o proxyfs_jsonrpc.o proxyfs_req_resp.o json_utils.o base64.o socket.o pool.o ioworker.o time_utils.o fault_inj.o test.o
	$(CC) -o $@ $(CFLAGS) $+ $(LDFLAGS)

install:
	cp -f proxyfs.h $(INCLUDEDIR)/.
	cp -f libproxyfs.so.1.0.0 $(LIBINSTALL)/libproxyfs.so.1.0.0
	ln -f -s libproxyfs.so.1.0.0 $(LIBINSTALL)/libproxyfs.so.1
	ln -f -s libproxyfs.so.1.0.0 $(LIBINSTALL)/libproxyfs.so

# the installcentos target is deprecated
#
installcentos:install

clean:
	rm -f *.o libproxyfs.so.1.0.0 libproxyfs.so.1 libproxyfs.so test pfs_log pfs_ping pfs_rw
