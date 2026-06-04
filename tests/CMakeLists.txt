
if (NOT BUILD_TESTS)
  return()
endif()

# XrdClCurlCommon holds shared test helpers (TransferTest, XrdOssSlowOpen) used
# by both the Curl- and Pelican-side test suites, so it builds unconditionally.
add_subdirectory(XrdClCurlCommon)
if( BUILD_XRDCL_CURL )
  add_subdirectory(XrdClCurl)
endif()
add_subdirectory(XrdClPelican)
if( BUILD_XRDCL_S3 )
  add_subdirectory(XrdClS3)
endif()
