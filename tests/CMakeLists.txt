
if (NOT BUILD_TESTS)
  return()
endif()

include(GoogleTest)

add_executable( xrdcl-transfer-test CopyTest.cc )
add_executable(xrdcl-pelican-test ParseTimeoutTest.cc DirectorCacheTest.cc HeaderParser.cc CurlWorker.cc)
target_link_libraries( xrdcl-transfer-test XrdClPelicanTesting GTest::gtest_main )
target_link_libraries( xrdcl-pelican-test XrdClPelicanTesting GTest::gtest_main )
target_include_directories( xrdcl-transfer-test PRIVATE ../src ${XRootD_INCLUDE_DIR} )
target_include_directories(xrdcl-pelican-test PRIVATE ../src ${XRootD_INCLUDE_DIR})

gtest_add_tests( TARGET xrdcl-transfer-test TEST_LIST TransferTests )
set_tests_properties( ${TransferTests}
  PROPERTIES
    FIXTURES_REQUIRED XrdClPelican::basic
    ENVIRONMENT "ENV_FILE=${CMAKE_BINARY_DIR}/tests/basic/setup.sh;XRD_PLUGINCONFDIR=${CMAKE_BINARY_DIR}/tests/basic/client.plugins.d"
)

gtest_discover_tests(xrdcl-pelican-test)

######################################
# Integration tests.
######################################
add_test(NAME XrdClPelican::basic::setup
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-setup.sh" basic)

set_tests_properties(XrdClPelican::basic::setup
  PROPERTIES
    FIXTURES_SETUP XrdClPelican::basic
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};SOURCE_DIR=${CMAKE_SOURCE_DIR};XROOTD_BINDIR=${XRootD_DATA_DIR}/../bin"
)

add_test(NAME XrdClPelican::basic::teardown
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-teardown.sh" basic)

set_tests_properties(XrdClPelican::basic::teardown
  PROPERTIES
    FIXTURES_CLEANUP XrdClPelican::basic
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR}"
)

add_test(NAME XrdClPelican::basic::test
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-test.sh" basic)

list(APPEND BASIC_TEST_LOGS ${CMAKE_CURRENT_BINARY_DIR}/tests/basic/pelican.log)
list(APPEND BASIC_TEST_LOGS ${CMAKE_CURRENT_BINARY_DIR}/tests/basic/client.log)

set_tests_properties(XrdClPelican::basic::test
  PROPERTIES
    FIXTURES_REQUIRED XrdClPelican::basic
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR}"
    ATTACHED_FILES_ON_FAIL "${BASIC_TEST_LOGS}"
)

add_test(NAME XrdClPelican::basic::stress_test
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-stress-test.sh" basic)

set_tests_properties(XrdClPelican::basic::stress_test
  PROPERTIES
    FIXTURES_REQUIRED XrdClPelican::basic
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR}"
    ATTACHED_FILES_ON_FAIL "${BASIC_TEST_LOGS}"
)

if (GoWrk)
  add_test(NAME XrdClPelican::basic::wrk_test
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-wrk-test.sh" basic)

  set_tests_properties(XrdClPelican::basic::wrk_test
    PROPERTIES
      FIXTURES_REQUIRED XrdClPelican::basic
      ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};WRK_BIN=${GoWrk}"
      ATTACHED_FILES_ON_FAIL "${BASIC_TEST_LOGS}")
endif()
