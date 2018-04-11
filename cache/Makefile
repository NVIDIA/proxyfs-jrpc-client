CC=gcc

CFLAGS=-I. -I/opt/ss/include -fPIC -g
# The -lrt flag is needed to avoid a link error related to clock_* methods if glibc < 2.17
LDFLAGS +=-lpthread -lm
DEPS = map.h cache.h key.h
LIBINSTALL?=/usr/lib
LIBINSTALL_CENTOS?=/usr/lib64
INCLUDEDIR?=/usr/include

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

#all: libcswift.so.1.0.0 test
all: libccache.so.1.0.0 test

libccache.so.1.0.0: cache.o map.o key.o
	$(CC) -shared -fPIC -o libccache.so.1.0.0 cache.o key.o map.o $(LDFLAGS) -lc
	ln -f -s ./libccache.so.1.0.0 ./libccache.so.1
	ln -f -s ./libccache.so.1.0.0 ./libccache.so

test: cache.o map.o key.o test.o
	$(CC) -o test cache.o key.o map.o test.o $(CFLAGS) $(LDFLAGS)

install:
	cp -f libccache.so.1.0.0 $(LIBINSTALL)/libccache.so.1.0.0
	ln -f -s $(LIBINSTALL)/libccache.so.1.0.0 $(LIBINSTALL)/libccache.so.1
	ln -f -s $(LIBINSTALL)/libccache.so.1.0.0 $(LIBINSTALL)/libccache.so

installcentos: all
	cp -f libccache.so.1.0.0 $(LIBINSTALL_CENTOS)/libccache.so.1.0.0
	ln -f -s $(LIBINSTALL_CENTOS)/libccache.so.1.0.0 $(LIBINSTALL_CENTOS)/libccache.so.1
	ln -f -s $(LIBINSTALL_CENTOS)/libccache.so.1.0.0 $(LIBINSTALL_CENTOS)/libccache.so

clean:
	rm -f *.o libccache.so.1.0.0 ./libccache.so.1 ./libccache.so test
