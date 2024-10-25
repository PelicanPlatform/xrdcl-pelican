
if (NOT BUILD_TESTS)
  return()
endif()

include(GoogleTest)

add_executable(xrdcl-pelican-test ParseTimeoutTest.cc ../src/ParseTimeout.cc)
target_include_directories(xrdcl-pelican-test PRIVATE ../src)

target_link_libraries(xrdcl-pelican-test XrdClPelican GTest::GTest GTest::Main)

gtest_discover_tests(xrdcl-pelican-test)

######################################
# Integration tests.
######################################
add_test(NAME XrdClPelican::basic::setup
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-setup.sh" basic)

set_tests_properties(XrdClPelican::basic::setup
  PROPERTIES
    FIXTURES_SETUP XrdClPelican::basic
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};SOURCE_DIR=${CMAKE_SOURCE_DIR}"
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
