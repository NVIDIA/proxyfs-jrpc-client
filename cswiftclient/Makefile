CC=gcc

CFLAGS=-I. -I/opt/ss/include -fPIC -g
# The -lrt flag is needed to avoid a link error related to clock_* methods if glibc < 2.17
LDFLAGS +=-lpthread -lm
DEPS = cswift.h sock_pool.h internal.h
LIBINSTALL?=/usr/lib
LIBINSTALL_CENTOS?=/usr/lib64
INCLUDEDIR?=/usr/include

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

#all: libcswift.so.1.0.0 test
all: libcswift.so.1.0.0 test test_range

libcswift.so.1.0.0: cswift.o headers.o sock_pool.o
	$(CC) -shared -fPIC -o libcswift.so.1.0.0 cswift.o headers.o sock_pool.o $(LDFLAGS) -lc
	ln -f -s ./libcswift.so.1.0.0 ./libcswift.so.1
	ln -f -s ./libcswift.so.1.0.0 ./libcswift.so

test: cswift.o headers.o sock_pool.o test.o
	$(CC) -o test cswift.o headers.o sock_pool.o test.o $(CFLAGS) $(LDFLAGS)

test_range: cswift.o headers.o sock_pool.o test_range.o
	$(CC) -o test_range cswift.o headers.o sock_pool.o test_range.o $(CFLAGS) $(LDFLAGS)

install:
	cp -f libcswift.so.1.0.0 $(LIBINSTALL)/libcswift.so.1.0.0
	ln -f -s $(LIBINSTALL)/libcswift.so.1.0.0 $(LIBINSTALL)/libcswift.so.1
	ln -f -s $(LIBINSTALL)/libcswift.so.1.0.0 $(LIBINSTALL)/libcswift.so

installcentos:
	cp -f libcswift.so.1.0.0 $(LIBINSTALL_CENTOS)/libcswift.so.1.0.0
	ln -f -s $(LIBINSTALL_CENTOS)/libcswift.so.1.0.0 $(LIBINSTALL_CENTOS)/libcswift.so.1
	ln -f -s $(LIBINSTALL_CENTOS)/libcswift.so.1.0.0 $(LIBINSTALL_CENTOS)/libcswift.so

clean:
	rm -f *.o libcswift.so.1.0.0 ./libcswift.so.1 ./libcswift.so test test_range
