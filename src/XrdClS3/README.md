
XrdClS3: An XRootD client plugin for S3-compatible APIs
=======================================================

The plugin in this directory provides the XRootD client with the
ability to use services that provide APIs compatible with Amazon's
[S3 protocol](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html).

The plugin implements `s3://` URI scheme which can interact with one
or more buckets in a service, depending on the plugin's configuration.

In the default configuration, the URL syntax is as follows:

```
s3://endpoint/bucket/object
```

In this case, `endpoint` is the hostname (and, optionally, port) of the S3 API
endpoint, `bucket` is the name of the bucket to use and `object` is the corresponding
object or key.  By default, we assume the region is `us-east-1`.  So, the following URL:

```
s3://s3.amazonaws.com/bucket-1/bar
```

will result internally in the following URL being used:

```
https://bucket-1.us-east-1.s3.amazonaws.com/bar
```

Plugin configuration
--------------------

The XrdClS3 plugin uses the XrdCl configuation system; configurations can be set
via environment-variables or via the C++ API.  It is layered on top of XrdClCurl;
any relevant configuration for XrdClCurl will also affect XrdClS3.

The following configurations values are known; environment variables are listed
first with C++ API keys in parenthesis.

- `XRDCLS3_ENDPOINT` (`XrdClS3Endpoint`; default is empty): The endpoint to use for
  the S3-compatible API.  See "Advanced URL Styles" below to understand how setting a
  default affects the possible URLs that can be generated.
- `XRDCLS3_REGION` (`XrdClS3Region`; default is `us-east-1`): The region to use for
  the client.
- `XRDCLS3_URLSTYLE` (`XrdClS3UrlStyle`; default is `virtual`): The S3 URL "style"; with
  the default (`virtual`), the bucket name is embedded in the URL's hostname; with `path`
  style, the bucket name is in the URL's resource.
- `XRDCLS3_MKDIRSENTINEL` (`XrdClS3MkdirSentinel`; default is `.xrdcls3.dirsentinel`): The
  name of the "hidden" object to create to indicate a "directory" created by the client. There
  is no concept of directories in S3; however, this allows the client to emulate concepts like
  empty directories and directory removal.  See the "Directory Emulation" section.
- `XRDCLS3_ACCESSKEYLOCATION` (`XrdClS3AccessKeyLocation`; default is empty): If set, the location
  of a file containing an access key to use for signing requests.  This key is used by default unless
  overridden by per-bucket configuraiton specified in `XRDCLS3_BUCKETCONFIGS`.
- `XRDCLS3_SECRETKEYLOCATION` (`XrdClS3SecretKeyLocation`; default is empty): If set, the location
  of a file containing a secret key to use for signing requests.  This key is used by default unless
  overridden by per-bucket configuraiton specified in `XRDCLS3_BUCKETCONFIGS`.
- `XRDCLS3_BUCKETCONFIGS` (`XrdClS3BucketConfigs`; default is empty): A space-separated list of additional
  configuration parameters that allow fine-grained control over the keys used for each bucket.

The list in `XRDCLS3_BUCKETCONFIGS` allows fine-grained control of the credentials used for
different S3 buckets.  For each configuration entry `BUCKET` in the space-separated list, the
following C++ API keys are used:

- `XrdClS3BUCKETBucketName`: The name of the bucket to use with this configuration.
- `XrdClS3BUCKETAccessKeyLocation`: The location of the access key to use for this bucket.
- `XrdClS3BUCKETSecretKeyLocation`: The location of the secret key to use for this bucket.

Advanced URL Styles
-------------------

If a default endpoint is set via `XRDCLS3_ENDPOINT`, additional URL styles are possible.

If set, any additional parts of the hostname are assumed to be the bucket name and the
region if the hostname ends in the default endpoint.  For example, suppose `XRDCLS3_ENDPOINT`
is set to `s3.amazaonaws.com`.  Then, the following URL:

```
s3://bucket-name.us-east-1.s3.amazonaws.com/object
```

is assumed to use the endpoint `s3.amazonaws.com`, bucket `bucket-name`, region `us-east-1`, and
object `object`.  The corresponding HTTPS URL is:

```
https://bucket-name.us-east-1.s3.amazonaws.com/object
```

If the hostname is set to the `XRDCLS3_ENDPOINT`, then the default URL style is assumed.

If the hostname _does not_ contain the value of `XRDCLS3_ENDPOINT`, then it is assumed to be the
bucket name.  So, in the `s3.amazonaws.com` example,

```
s3://bucket-name/some-object-name
```

becomes

```
https://bucket-name.us-east-1.s3.amazonaws.com/some-object-name
```

Setting the endpoint name provides fine-grained control of both the region and bucket from the URL
given to the XRootD client, which may be advantageous in some situations. In some non-AWS cases,
the region is ignored, meaning the (simpler) default syntax is more useful.

Use with the XRootD Caching Proxy Server
----------------------------------------

The client plugin can be used with the XRootD server when run in caching proxy mode; this allows the
server to have the S3 object store as a backend and cache objects locally.  This may be useful if there
are high egress costs to move objects out of S3 and gains from managing a copies outside due to reuse.

In this case, you can configure via `pss.origin`.  In the example of Amazon S3, the configuration would be:

```
ofs.osslib libXrdPss.so
pss.origin s3://s3.amazonaws.com
pss.cachelib libXrdPfc.so
oss.localroot /tmp/xrootd-cache
```

All the standard `pss.*` and `pfc.*` configuration options apply.  To further configure the client plugin,
you will need to set the Unix environment variables for the server.

Writing to S3
-------------

S3 requires that all object uploads declare their size upfront; uploads also must be done sequentially with
no out-of-order writes.

This is enforced by the client plugin.  Direct users of the API must specify the `oss.asize` query parameter
in the URL when opening a file for write.  For example:

```
s3://s3.amazonaws.com/bucket-name/object-for-upload?oss.asize=1024
```

will result in a new object, `object-for-upload`, of size 1024 bytes.  If you do not write the full size -
or if you write more than the declared size - an error will occur and the object will not be created in S3.

If the plugin is used as part of a proxy setup, note that `oss.asize` will automatically be set internally
if the client is uploading to the proxy using HTTPS and sets the `Content-Length` header.

The writes from the client are streamed to S3 as a single `PUT` operation with no internal buffering; any
out-of-order writes will result in an error.

__Note__: The S3 protocol has the concept of a multi-chunk upload that would allow us to relax the restriction
of knowing the object size up-front.  However, practical use has shown that finalizing the upload (implemented
during the `Close()` method) results in potentially long delays (Amazon's documentation notes this can be minutes)
which has caused client timeouts.  Accordingly, that approach was abandoned and we pass the restriction on
to the users of this client.

Directory Emulation
-------------------

The contents of a bucket have no structure or hierarchy within the object names.  However, the XRootD
client provides a POSIX-like API which contains directory concepts so it is useful to map from
object names to a directory hierarchy.  We treat the `/` character as a separator so an object name

```
/foo/bar/baz
```

when accessed via the XRootD client can be the `baz` "filename" within the `/foo/bar` "directory".

__Unfortunately, the mapping between concepts is not perfect.__

For example, suppose the following objects exist:

```
/foo/bar
```

and

```
/foo/bar/baz
```

In this case, should we consider `/foo/bar` a "file" or a "directory"?  In this implementation, we
treat it as a file, meaning that while `/foo/bar/baz` may be readable directory, _one cannot find it
via walking the directory structure_!

We "detect" directories by querying to see if there are objects with a common prefix.  So, if

```
/foo/bar/one
```

and

```
/foo/bar/two
```

both exist, then we assume `/foo/bar` is a directory with contents containing `.`, `..`, `one`, and `two`.

This presents a problem in creating "empty" directories: if we detect their existence by the objects inside,
how can we create an empty directory?  How do we remove a directory?  For this, the plugin uses the concept
of a "sentinel object".  This is an empty object whose existence indicates the existence of an emulated
directory but does not show up in directory listings and cannot be "read" through the client API.

So, if one creates a directory named `/foo` in an empty bucket and then lists the bucket with S3-native tools,
one would see the following object name:

```
/foo/.xrdcls3.dirsentinel
```

(the name of the sentinel can be controlled by the client configuration)

However, if you listed the emulated directory via the XRootD client, `/foo` would show up as an empty directory.