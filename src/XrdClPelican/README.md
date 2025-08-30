XrdCl Plugin for the `pelican://` protocol
==========================================

The `XrdClPelican` plugin provides an implementation of the `pelican://`
protocol used by the [Pelican Platfrom](https://pelicanplatform.org).

The `pelican://` protocol is based on HTTPS (the implementation internally
leverages `XrdClCurl`) and provides the following functionality:

- Service discovery protocol allowing the central director service to be
  located separately from the metadata lookup.
- Checksum lookup caching on the client-side
- Origin selection cache, allowing the client to skip the director queries
  if it's recently been sent to an origin serving the same namespace.
- Connection brokering functionality, allowing the downloading from
  origins that have no incoming connectivity.

Configuration
-------------

An installed plugin will automatically enable itself for the `pelican://`
protocol.  The following environment variables control the client configuration
(the corresponding C++ API configuration names are given parenthetically):

- `XRD_PELICANBROKERSOCKET` (`PelicanBrokerSocket`): The location of the Unix
  domain socket for communicating with the local broker service.
- `XRD_PELICANMINIMUMHEADERTIMEOUT` (`PelicanMinimumHeaderTimeout`): The minimum
  time the client can request for a timeout for a response; by default, set to 2s
  (2 seconds).  Floating point and other suffixes are accepted.
- `XRD_PELICANDEFAULTHEADERTIMEOUT` (`PelicanDefaultHeaderTimeout`): The default
  header timeout to use if one is not specified by the client request.  By default,
  set to 9.5s.
- `XRD_PELICANFEDERATIONMETADATATIMEOUT` (`PelicanFederationMetadataTimeout`): The
  timeout for discovering the federation's metadata (including the location of the
  director service).
- `XRD_PELICANCACHETOKENLOCATION` (`PelicanCacheTokenLocation`): The location of
  a token identifying the cache.  If set, the contents of the file will be sent
  along with any client provided tokens as a separate `Authorization` header.
