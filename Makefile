CC=gcc
CFLAGS=-I. -I/opt/ss/include -fPIC -g -D _GNU_SOURCE
# The -lrt flag is needed to avoid a link error related to clock_* methods if glibc < 2.17
LDFLAGS += -ljson-c -lpthread -L/opt/ss/lib64 -lrt -lm

DEPS = base64.h debug.h fault_inj.h ioworker.h json_utils.h json_utils_internal.h pool.h proxyfs.h proxyfs_jsonrpc.h proxyfs_req_resp.h proxyfs_testing.h socket.h synchron.h time_utils.h

LIBINSTALL?=/usr/lib
LIBINSTALL_CENTOS?=/usr/lib64

INCLUDEDIR?=/usr/include

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

all: libproxyfs.so.1.0.0 test

libproxyfs.so.1.0.0: proxyfs_api.o proxyfs_jsonrpc.o proxyfs_req_resp.o json_utils.o base64.o socket.o pool.o ioworker.o time_utils.o fault_inj.o synchron.o
	$(CC) -shared -fPIC -Wl,-soname,libproxyfs.so.1 -o $@ $+ $(LDFLAGS) -lc
	ln -f -s ./libproxyfs.so.1.0.0 ./libproxyfs.so.1
	ln -f -s ./libproxyfs.so.1.0.0 ./libproxyfs.so


test: proxyfs_api.o proxyfs_jsonrpc.o proxyfs_req_resp.o json_utils.o base64.o socket.o pool.o ioworker.o time_utils.o fault_inj.o test.o synchron.o
	$(CC) -o $@ $(CFLAGS) $+ $(LDFLAGS)

install:
	cp -f ./proxyfs.h $(INCLUDEDIR)/.
	@if [ ! -f /etc/os-release ]; then \
		echo "ERROR: Could not determine OS environment; /etc/os-release does not exist" 1>&2; \
		exit 2; \
	fi
	@. /etc/os-release; \
	case "X$$ID" in \
	Xcentos) LIBDIR=$(LIBINSTALL_CENTOS); \
		;; \
	Xubuntu) LIBDIR=$(LIBINSTALL); \
		;; \
	X) \
		echo "ERROR: /etc/os-release does not specify a value for 'ID'" 1>&2; \
		exit 2; \
		;; \
	*) \
		echo "ERROR: /etc/os-release specified an unknown 'ID' '$ID'" 1>&2; \
		exit 2; \
		;; \
	esac; \
	echo cp -f libproxyfs.so.1.0.0 $$LIBDIR/libproxyfs.so.1.0.0; \
	cp -f libproxyfs.so.1.0.0 $$LIBDIR/libproxyfs.so.1.0.0; \
	echo ln -f -s libproxyfs.so.1.0.0 $$LIBDIR/libproxyfs.so.1; \
	ln -f -s libproxyfs.so.1.0.0 $$LIBDIR/libproxyfs.so.1; \
	echo ln -f -s libproxyfs.so.1.0.0 $$LIBDIR/libproxyfs.so; \
	ln -f -s libproxyfs.so.1.0.0 $$LIBDIR/libproxyfs.so

# the installcentos target is deprecated
#
installcentos:install

clean:
	rm -f *.o libproxyfs.so.1.0.0 libproxyfs.so.1 libproxyfs.so test pfs_log pfs_ping pfs_rw
