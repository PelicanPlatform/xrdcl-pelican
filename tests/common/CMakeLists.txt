
if( NOT BUILD_TESTS )
  return()
endif()

add_library( XrdClCurlTransferTest
  TransferTest.cc TransferTest.hh
)

target_link_libraries( XrdClCurlTransferTest XrdClCurlTesting XRootD::XrdCl GTest::gtest_main )

# The XrdOssSlowOpen module allows us to test what happens when the origin times out
# while opening a file.
add_library( XrdOssSlowOpen MODULE XrdOssSlowOpen.cc )
target_link_libraries( XrdOssSlowOpen XRootD::XrdUtils XRootD::XrdServer )
set_target_properties( XrdOssSlowOpen PROPERTIES OUTPUT_NAME "XrdOssSlowOpen-${XRootD_PLUGIN_VERSION}" SUFFIX ".so" )

