
if (NOT BUILD_TESTS)
  return()
endif()

include(GoogleTest)

add_executable( xrdcl-transfer-test ChecksumTest.cc CopyTest.cc TransferTest.cc VectorReadTest.cc WriteTest.cc )
add_executable( xrdcl-pelican-test ParseTimeoutTest.cc DirectorCacheTest.cc HeaderParser.cc CurlWorker.cc ChecksumCache.cc )
target_link_libraries( xrdcl-transfer-test XrdClCurlTesting XrdClPelicanTesting GTest::gtest_main )
target_link_libraries( xrdcl-pelican-test XrdClCurlTesting XrdClPelicanTesting GTest::gtest_main )
target_include_directories( xrdcl-transfer-test PRIVATE ../src ${XRootD_INCLUDE_DIR} )
target_include_directories( xrdcl-pelican-test PRIVATE ../src ${XRootD_INCLUDE_DIR} )

# The XrdOssSlowOpen module allows us to test what happens when the origin times out
# while opening a file.
add_library( XrdOssSlowOpen MODULE xrdoss_slowopen.cc )
target_include_directories( XrdOssSlowOpen PRIVATE ${XRootD_INCLUDE_DIRS} )
target_link_libraries( XrdOssSlowOpen ${XRootD_UTILS_LIBRARIES} ${XRootD_SERVER_LIBRARIES} )
set_target_properties( XrdOssSlowOpen PROPERTIES OUTPUT_NAME "XrdOssSlowOpen-${XRootD_PLUGIN_VERSION}" SUFFIX ".so" )

gtest_add_tests( TARGET xrdcl-transfer-test TEST_LIST TransferTests )
set_tests_properties( ${TransferTests}
  PROPERTIES
    FIXTURES_REQUIRED XrdClPelican::basic
    ENVIRONMENT "ENV_FILE=${CMAKE_BINARY_DIR}/tests/basic/setup.sh;XRD_PLUGINCONFDIR=${CMAKE_BINARY_DIR}/tests/basic/client.plugins.d;LD_LIBRARY_PATH=${XRootD_LIB_DIR}:$ENV{LD_LIBRARY_PATH}"
)

gtest_add_tests( TARGET xrdcl-pelican-test TEST_LIST PelicanTests )
if( CMAKE_SYSTEM_NAME STREQUAL "Linux" )
  set_tests_properties( ${PelicanTests}
    PROPERTIES
      ENVIRONMENT "LD_LIBRARY_PATH=${XRootD_LIB_DIR}:$ENV{LD_LIBRARY_PATH}"
  )
endif()

######################################
# Ensure pelican server is available
######################################
find_program(PELICAN_BIN pelican HINTS "${CMAKE_CURRENT_BINARY_DIR}")
if( NOT PELICAN_BIN )
  # Example URL:
  # https://dl.pelicanplatform.org/7.14.2/pelican_Linux_arm64.tar.gz
  set( PELICAN_VERSION "7.14.2" )
  if( APPLE )
      set( SYS_NAME "Darwin" )
  else()
      set( SYS_NAME "Linux" )
  endif()
  if( CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" )
    set( SYS_PROC "arm64" )
  else()
    set( SYS_PROC "x86_64" )
  endif()

  set( PELICAN_URL "https://dl.pelicanplatform.org/${PELICAN_VERSION}/pelican_${SYS_NAME}_${SYS_PROC}.tar.gz" )
  set( PELICAN_HASH "000000000" )
  if( SYS_NAME STREQUAL "Darwin" AND SYS_PROC STREQUAL "x86_64" )
    set( PELICAN_HASH "6ef9370f6c9e7fa8ec1aae197b7b18324ffdaecbad61e3754a49f5d4ce2b575d" )
  elseif( SYS_NAME STREQUAL "Darwin" AND SYS_PROC STREQUAL "arm64" )
    set( PELICAN_HASH "7e8f97ab8d364ed4e6a6e69324a8c7e6ab8cda8c85e9aba47f7f6a83ad124e1b" )
  elseif( SYS_NAME STREQUAL "Linux" AND SYS_PROC STREQUAL "x86_64" )
    set( PELICAN_HASH "e2aa7faa4b0727557185c5c81d594c62aa38adb76ddac9ec6580714d48cc06c4" )
  elseif( SYS_NAME STREQUAL "Linux" AND SYS_PROC STREQUAL "arm64" )
    set( PELICAN_HASH "a7d0d9226511c18bd17bcd3878d30c8629a062237610aba45f99dedb24d40097" )
  endif()
  file( DOWNLOAD "${PELICAN_URL}" "${CMAKE_CURRENT_BINARY_DIR}/pelican-v${PELICAN_VERSION}.tar.gz" EXPECTED_HASH "SHA256=${PELICAN_HASH}" )
  file( ARCHIVE_EXTRACT INPUT "${CMAKE_CURRENT_BINARY_DIR}/pelican-v${PELICAN_VERSION}.tar.gz" PATTERNS "pelican-${PELICAN_VERSION}/pelican" )
  find_program( PELICAN_BIN pelican HINTS "${CMAKE_CURRENT_BINARY_DIR}/pelican-${PELICAN_VERSION}" REQUIRED )
endif()

######################################
# Integration tests.
######################################
add_test(NAME XrdClPelican::basic::setup
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-setup.sh" basic)

set_tests_properties(XrdClPelican::basic::setup
  PROPERTIES
    FIXTURES_SETUP XrdClPelican::basic
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};PELICAN_BIN=${PELICAN_BIN};SOURCE_DIR=${CMAKE_SOURCE_DIR};XROOTD_BINDIR=${XRootD_DATA_DIR}/../bin;XROOTD_LIBDIR=${XRootD_LIB_DIR}"
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
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};XROOTD_BINDIR=${XRootD_DATA_DIR}/../bin;XROOTD_LIBDIR=${XRootD_LIB_DIR}"
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
