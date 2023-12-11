
Xrootd Client integration for Pelican
=====================================

This repository contains a simple integration between the Xrootd client (`XrdCl`; used both by
the command line tools like `xrdcp` and the XCache configuration of the server) and Pelican.  It
uses libcurl to provide generic HTTP functionality and can understand Pelican-specific headers
and semantics.

Building and Installing
-----------------------

The plugin requires a C++14 compiler and CMake 3.16 or higher; on RHEL7, this can be provided
by the `devtoolset-11-toolchain` package.

To build and install, after checking out the source code:

```
mkdir build
cd build
cmake ..
make && make install
```

Provide the `-DCMAKE_INSTALLPREFIX` flag to `cmake` to override the install location.
