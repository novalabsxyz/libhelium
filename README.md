libhelium
=========

An efficient, cross-platform interface to the Helium platform.

Example
=======

~~~c
#include <helium.h>

// create a new connection
helium_collection_t *conn = helium_alloc();

// associate it with a proxy (if you don't have direct ipv6 connectivity) and callback function pointer
helium_open(conn, NULL, my_callback_function);

// you can also use block syntax if you have built libhelium with block support
helium_open_b(conn, NULL, ^(const helium_connection_t *conn, uint64_t mac, char *msg, size_t n) {
	printf("Received the string '%s' from MAC address %lX", msg, mac);
});

// subscribe to events from a given MAC address
helium_subscribe(conn, 0x0000112233440001, "magic_helium_token");

// send data to a device at a given mac address
helium_send(conn, 0x0000112233440001, "magic_helium_token", "Main screen turn on", strlen("Main screen turn on"));

// unsubscribe from a device if you don't want to see any more events from it
helium_unsubscribe(conn, 0x0000112233440001);
~~~

Requirements
============

libhelium depends on [libuv](https://github.com/joyent/libuv) (>= 0.11.29) for cross-platform network functionality and OpenSSL (>= 1.0.1) for required cipher suites. Optional unit test infrastructure is provided by [cunit](http://cunit.sourceforge.net).


## OS X

You can download a prepackaged OS X installer [here](https://github.com/helium/libhelium/releases/tag/0.1.0). Should you wish to compile from source, you'll need cmake, libuv and openssl (please note that the OpenSSL included with Darwin will *not* work). Assuming you have [Homebrew](http://brew.sh) installed:

    brew install cmake
    brew install openssl
    brew install --devel libuv

## Linux

You'll need libuv. Install it from git or with your favorite package manager. You'll need `clang` and [`libblocksruntime`](http://mackyle.github.io/blocksruntime/) if you want to build with C blocks support on.

### Debian and Ubuntu packages

You can install the prerequisite packages (other than cmake and libuv) with:

    apt-get update && apt-get install -y autoconf automake build-essential \
    clang doxygen git libblocksruntime-dev libcunit1-dev libssl-dev libtool \
    wget

### cmake

3.0 or higher is required, if your package manager doesn't have cmake 3, then build from source:

    wget http://www.cmake.org/files/v3.0/cmake-3.0.2.tar.gz
    tar -zxf cmake-3.0.2.tar.gz
    cd cmake-3.0.2/
    ./bootstrap && make && make install

### libuv

To build from source:

    git clone https://github.com/joyent/libuv
    cd libuv
    sh autogen.sh
    ./configure
    make
    make install

### CUnit

libhelium will use cunit if you call `make test` and cunit is available.  On Debian it is simple as

    apt-get install libcunit1-dev

Then run `make test` after the cmake and make builds.

Building
========


    git clone git@github.com:helium/libhelium ; cd libhelium
    mkdir build ; cd build
    cmake ..
    make

### Documentation

If you want to build the documentation, you'll need [Doxygen](http://www.stack.nl/~dimitri/doxygen/). Run `make doc` to build it; the output will be placed in an `html/` folder.

Testing
=======


The `shell` executable listens on stdin for lines of the form `<MAC> <token> <message>`. Sending the single character `'s'` tests the subscription features.

For example (using a ipv4->ipv6 proxy at r01.foo.example.io):

    ./shell -p r01.foo.example.io
    ...
    00212effffffffff 34dcxtSTIsyLFZ6Tffffff== s

will subscribe you to messages from device 00212effffffffff that is being proxied through r01.

Info
====

libhelium is copyright (c) Helium Systems, Inc. and distributed to the public under the terms of the MIT license.
