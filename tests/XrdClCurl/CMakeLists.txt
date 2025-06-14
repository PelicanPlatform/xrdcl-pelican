
if( NOT BUILD_TESTS )
  return()
endif()

include( GoogleTest )

find_program( OPENSSL_BIN openssl REQUIRED )
find_package( SciTokensCpp REQUIRED )

# All tests that only depend on the pure XrdCl interfaces and
# have no linkage against XrdClCurl
add_executable( xrdcl-test
  ChecksumTest.cc
  ConnectionCalloutTest.cc
  DeleteTest.cc
  MkcolTest.cc
  ReadTest.cc
  WriteTest.cc
)

# Tests depending on XrdClCurl linkage
add_executable( xrdcl-curl-test
  CopyTest.cc
  ParseTimeoutTest.cc
  VectorReadTest.cc
)

target_link_libraries( xrdcl-test XrdClCurlTransferTest nlohmann_json::nlohmann_json GTest::gtest_main )
target_link_libraries( xrdcl-curl-test XrdClCurlTesting XrdClCurlTransferTest GTest::gtest_main )

gtest_add_tests( TARGET xrdcl-test TEST_LIST CurlClOnlyTests )
set_tests_properties( ${CurlClOnlyTests}
  PROPERTIES
    FIXTURES_REQUIRED XrdClCurl::curl
    ENVIRONMENT "ENV_FILE=${CMAKE_BINARY_DIR}/tests/curl/setup.sh;XRD_PLUGINCONFDIR=${CMAKE_BINARY_DIR}/tests/curl/client.plugins.d;LD_LIBRARY_PATH=${XRootD_LIB_DIR}:$ENV{LD_LIBRARY_PATH}"
)

gtest_add_tests( TARGET xrdcl-curl-test TEST_LIST CurlTests )
set_tests_properties( ${CurlTests}
  PROPERTIES
    FIXTURES_REQUIRED XrdClCurl::curl
    ENVIRONMENT "ENV_FILE=${CMAKE_BINARY_DIR}/tests/curl/setup.sh;XRD_PLUGINCONFDIR=${CMAKE_BINARY_DIR}/tests/curl/client.plugins.d;LD_LIBRARY_PATH=${XRootD_LIB_DIR}:$ENV{LD_LIBRARY_PATH}"
)

######################################
# Helper programs for tokens
######################################
add_executable(xrdscitokens-create-jwks XrdScitokensCreateJwks.cc)
target_link_libraries(xrdscitokens-create-jwks PRIVATE OpenSSL::Crypto)

add_executable(xrdscitokens-create-token XrdScitokensCreateToken.cc)
target_link_libraries(xrdscitokens-create-token
  PRIVATE
    ${SCITOKENS_CPP_LIBRARIES}
)
target_include_directories(xrdscitokens-create-token
  PRIVATE
    ${SCITOKENS_CPP_INCLUDE_DIR}
)


######################################
# Integration tests.
######################################
add_test(NAME XrdClCurl::curl::setup
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/curl-setup.sh" curl)

set_tests_properties( XrdClCurl::curl::setup
  PROPERTIES
    FIXTURES_SETUP XrdClCurl::curl
    ENVIRONMENT "OPENSSL_BIN=${OPENSSL_BIN};BINARY_DIR=${CMAKE_BINARY_DIR};SOURCE_DIR=${CMAKE_SOURCE_DIR};XROOTD_BINDIR=${XRootD_BIN_DIR};XROOTD_LIBDIR=${XRootD_LIB_DIR}"
)

add_test( NAME XrdClCurl::curl::teardown
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/curl-teardown.sh" curl)

set_tests_properties( XrdClCurl::curl::teardown
  PROPERTIES
    FIXTURES_CLEANUP XrdClCurl::curl
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR}"
)

add_test( NAME XrdClCurl::curl::test
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/curl-test.sh" curl)

list( APPEND CURL_TEST_LOGS ${CMAKE_CURRENT_BINARY_DIR}/tests/curl/origin.log )
list( APPEND CURL_TEST_LOGS ${CMAKE_CURRENT_BINARY_DIR}/tests/curl/cache.log )
list( APPEND CURL_TEST_LOGS ${CMAKE_CURRENT_BINARY_DIR}/tests/curl/client.log )

set_tests_properties( XrdClCurl::curl::test
  PROPERTIES
    FIXTURES_REQUIRED XrdClCurl::curl
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};XROOTD_BINDIR=${XRootD_DATA_DIR}/../bin;XROOTD_LIBDIR=${XRootD_LIB_DIR}"
    ATTACHED_FILES_ON_FAIL "${CURL_TEST_LOGS}"
)
