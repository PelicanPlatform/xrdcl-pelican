
if (NOT BUILD_TESTS)
  return()
endif()

add_subdirectory(XrdClCurlCommon)
add_subdirectory(XrdClCurl)
add_subdirectory(XrdClPelican)
add_subdirectory(XrdClS3)
