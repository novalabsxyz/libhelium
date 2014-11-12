# Packaging

This is a standalone makefile that will attempt ot package libhelium using FPM.  You can find FPM [on its github page](https://github.com/jordansissel/fpm) with full install instructions.

Currently only OSX, Debian, and CentOS have been tested.

To make a package:

```
make package
```

You can optionally pass in a `PKG_BUILD` setting on the command line to roll a package rev past 1 (the default).
