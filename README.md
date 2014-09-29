libhelium
=========

low-level, cross-platform interface to Helium routers and bridges

requirements
============

## OS X

You'll need [libuv](https://github.com/joyent/libuv) and libcrypto (a newer one than the system OS X). Assuming you have [Homebrew](http://brew.sh) installed:

```
brew install openssl
brew install --devel libuv
```

## Linux

You'll need `clang` and [`libblocksruntime`](http://mackyle.github.io/blocksruntime/) if you want to build with C blocks support on.

building
========

```
  git clone
  mkdir build
  cd build
  cmake ..
  make
```
