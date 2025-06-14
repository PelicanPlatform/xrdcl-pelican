
if( NOT BUILD_TESTS )
  return()
endif()

include( GoogleTest )

add_executable( xrdcl-pelican-test
  CacheToken.cc
  ChecksumCache.cc
  ChecksumTest.cc
  DirectorCacheTest.cc
  HeaderParser.cc
)

target_link_libraries( xrdcl-pelican-test XrdClPelicanTesting XrdClCurlTesting XrdClCurlTransferTest GTest::gtest_main )

gtest_add_tests( TARGET xrdcl-pelican-test TEST_LIST PelicanTests )
set_tests_properties( ${PelicanTests}
  PROPERTIES
    FIXTURES_REQUIRED XrdClPelican::pelican
    ENVIRONMENT "XRD_LOGLEVEL=Debug;ENV_FILE=${CMAKE_BINARY_DIR}/tests/pelican/setup.sh;XRD_PLUGINCONFDIR=${CMAKE_BINARY_DIR}/tests/pelican/client.plugins.d;LD_LIBRARY_PATH=${XRootD_LIB_DIR}:$ENV{LD_LIBRARY_PATH}"
)

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
add_test(NAME XrdClPelican::pelican::setup
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-setup.sh" pelican)

set_tests_properties( XrdClPelican::pelican::setup
  PROPERTIES
    FIXTURES_SETUP XrdClPelican::pelican
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};PELICAN_BIN=${PELICAN_BIN};SOURCE_DIR=${CMAKE_SOURCE_DIR};XROOTD_BINDIR=${XRootD_DATA_DIR}/../bin;XROOTD_LIBDIR=${XRootD_LIB_DIR}"
)

add_test( NAME XrdClPelican::pelican::teardown
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-teardown.sh" pelican)

set_tests_properties( XrdClPelican::pelican::teardown
  PROPERTIES
    FIXTURES_CLEANUP XrdClPelican::pelican
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR}"
)

add_test( NAME XrdClPelican::pelican::test
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-test.sh" pelican)

list( APPEND PELICAN_TEST_LOGS ${CMAKE_CURRENT_BINARY_DIR}/tests/pelican/pelican.log )
list( APPEND PELICAN_TEST_LOGS ${CMAKE_CURRENT_BINARY_DIR}/tests/pelican/client.log )

set_tests_properties( XrdClPelican::pelican::test
  PROPERTIES
    FIXTURES_REQUIRED XrdClPelican::pelican
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};XROOTD_BINDIR=${XRootD_DATA_DIR}/../bin;XROOTD_LIBDIR=${XRootD_LIB_DIR}"
    ATTACHED_FILES_ON_FAIL "${PELICAN_TEST_LOGS}"
)

if (GoWrk)
  add_test(NAME XrdClPelican::pelican::wrk_test
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/pelican-wrk-test.sh" pelican)

  set_tests_properties(XrdClPelican::pelican::wrk_test
    PROPERTIES
      FIXTURES_REQUIRED XrdClPelican::pelican
      ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};WRK_BIN=${GoWrk}"
      ATTACHED_FILES_ON_FAIL "${PELICAN_TEST_LOGS}")
endif()
