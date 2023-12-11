
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

Provide the `-DCMAKE_INSTALL_PREFIX` flag to `cmake` to override the install location.

Using from the command line
---------------------------

By default, the install drops the plugin configuration into `/etc/xrootd/client.plugins.d/`;
if you do a non-root installation, you must override the location of the client plugin directory
with the `XRD_PLUGINCONFDIR` environment variable.

The `xrdcp` client disables the HTTP protocol by default; set `XRDCP_ALLOW_HTTP=true` to enable it.

An example invocation including these two environment variables would be:

```
XRDCP_ALLOW_HTTP=true XRD_PLUGINCONFDIR=$RELEASE_DIR/etc/xrootd/client.plugins.d/ \
xrdcp -f http://unl-cache.nationalresearchplatform.org:8000/nrp/cachetest/100gfile
```

where `$RELEASE_DIR` is set to the value of `CMAKE_INSTALL_PREFIX`.

Note the install of the `xrdcl-http` RPM will cause `xrdcl-http` to be used by default.  If this is not
desired, remove or comment out `/etc/xrootd/client.plugins.d/xrdcl-http-plugin.conf` (do *not* just set
`enable=false` -- the presence of the entry will cause it to match).

To verify the pelican plugin is used, pass `-d 3` and look for log messages from `XrdClPelican` as in:

```
[2023-12-11 07:39:38.926434 -0600][Debug  ][XrdClPelican      ]
PgRead http://unl-cache.nationalresearchplatform.org:8000/nrp/cachetest/100gfile
(131072 bytes at offset 1132855296)
```

(line breaks were added for readability).

Using from XCache
-----------------

Enable the use of the plugin at the system level; ensure the command-line use functions (it may be possible
to override solely through the CLI; a system/container level install is simpler).

Add the following two lines to the XRootD server configuration:

```
pss.setopt DebugLevel 4
pss.origin https://director-caches.osg-htc.org:443
```

Then issue GET requests to the cache endpoint (substitute `localhost` below as appropriate):

```
$ curl http://localhost:8000/nrp/cachetest/100gfile > /dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0  100G    0 20.0M    0     0  3320k      0  8:46:18  0:00:06  8:46:12 3967k^C
```

Adjust for your setup.  Note that XRootD 5.6.3 and earlier will crash if a port number is not provided.
Once you verify the plugin is working and can download from the cache, we recommend a lower debug level
for production use.
