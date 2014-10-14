libhelium
=========

low-level, cross-platform interface to Helium routers and bridges

example
=======

```c
#include <helium.h>

// create a new connection
helium_collection_t *conn = helium_alloc(NULL);

// associate it with a callback (with function pointers or, if you're fancy C/C++ lambdas)
helium_open_b(conn, ^(const helium_connection_t *conn, uint64_t mac, char *msg, size_t n) {
    printf("Received the string '%s' from MAC address %lX", msg, mac);
});

// subscribe to events from a given MAC address
helium_subscribe(conn, 0x0000112233440001, "magic_helium_token");
```

requirements
============

libhelium depends on [libuv](https://github.com/joyent/libuv) (>= 0.11.29) for cross-platform network functionality.


## OS X

You'll need cmake, libuv and libcrypto (a newer one than the system OS X). Assuming you have [Homebrew](http://brew.sh) installed:

```
brew install cmake
brew install openssl
brew install --devel libuv
```

## Linux

You'll need libuv. Install it from git or with your favorite package manager. You'll need `clang` and [`libblocksruntime`](http://mackyle.github.io/blocksruntime/) if you want to build with C blocks support on.

building
========

```
  git clone git@github.com:nervcorp/libhelium ; cd libhelium
  mkdir build ; cd build
  cmake ..
  make
```

testing
=======

The `helium_test` executable listens on stdin for lines of the form `<MAC> <token> <message>`. Sending the single character `'s'` tests the subscription features.

For example:

```
./helium_test -p r01.foo.example.io
...
00212effffffffff 29dcxtSTIsyGFZ6Tffffff== s
```

will subscribe you to messages from device 00212effffffffff that is being routed through r01.

info
====

libhelium is copyright (c) Helium Systems, Inc. and distributed to the public under the terms of the 3-clause BSD liense.
