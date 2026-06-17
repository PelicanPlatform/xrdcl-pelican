
if( NOT BUILD_TESTS )
  return()
endif()

include( GoogleTest )

add_executable( xrdcl-pelican-test
  CacheToken.cc
  ChecksumTest.cc
  DirectorTest.cc
  RedirectIntegrationTest.cc
  RetryIntegrationTest.cc
  WritebackTest.cc
)

# Unit tests that do not require the pelican fixture
add_executable( xrdcl-pelican-unit
  EndpointOverrideTest.cc
  ChecksumCache.cc
  DirectorCacheTest.cc
  HeaderParser.cc
  TokenDiscoveryTest.cc
  RetryTest.cc
)

target_link_libraries( xrdcl-pelican-test XrdClPelicanTesting XrdClCurlTransferTest GTest::gtest_main )
target_link_libraries( xrdcl-pelican-unit XrdClPelicanTesting XRootD::XrdCl GTest::gtest_main )

# The standalone unit tests do not need a running Pelican federation; always register them.
gtest_add_tests( TARGET xrdcl-pelican-unit TEST_LIST PelicanUnitTests )
set_tests_properties( ${PelicanUnitTests}
  PROPERTIES
    ENVIRONMENT "LD_LIBRARY_PATH=${XRootD_LIB_DIR}"
)

# The Pelican federation integration tests stand up a `pelican serve` instance, which
# requires the PelicanPlatform XRootD fork: this is not available at time of writing
# for XRootD 6.  The xrdcl-pelican-test binary is still built
# (compile coverage), just not registered/run.  Override with -DENABLE_PELICAN_INTEGRATION_TESTS=ON
# if a compatible Pelican / XRootD combination becomes available.
if( XRootD_PLUGIN_VERSION GREATER_EQUAL 6 )
  set( ENABLE_PELICAN_INTEGRATION_TESTS_DEFAULT OFF )
else()
  set( ENABLE_PELICAN_INTEGRATION_TESTS_DEFAULT ON )
endif()
option( ENABLE_PELICAN_INTEGRATION_TESTS
  "Run the Pelican federation integration tests (needs the PelicanPlatform XRootD fork; unavailable for XRootD>=6)"
  ${ENABLE_PELICAN_INTEGRATION_TESTS_DEFAULT} )

if( NOT ENABLE_PELICAN_INTEGRATION_TESTS )
  message( STATUS "Pelican federation integration tests: disabled (XRootD plugin version ${XRootD_PLUGIN_VERSION})" )
  return()
endif()

gtest_add_tests( TARGET xrdcl-pelican-test TEST_LIST PelicanTests )
set_tests_properties( ${PelicanTests}
  PROPERTIES
    FIXTURES_REQUIRED XrdClPelican::pelican
    ENVIRONMENT "XRD_LOGLEVEL=Debug;LSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/leaksanitizer-suppress.txt;ENV_FILE=${CMAKE_BINARY_DIR}/tests/pelican/setup.sh;XRD_PLUGINCONFDIR=${CMAKE_BINARY_DIR}/tests/pelican/client.plugins.d;LD_LIBRARY_PATH=${XRootD_LIB_DIR}:$ENV{LD_LIBRARY_PATH}"
)

######################################
# Ensure pelican server is available
######################################
find_program(PELICAN_BIN pelican HINTS "${CMAKE_CURRENT_BINARY_DIR}")
if( NOT PELICAN_BIN )
  # Example URL:
  # https://dl.pelicanplatform.org/7.25.0/pelican_Linux_arm64.tar.gz
  #
  # Version requirement bumped to v7.25.0 to grab POSIXv2 backend, allowing for
  # a regression test on issue #116.
  set( PELICAN_VERSION "7.25.0" )
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
    set( PELICAN_HASH "5d635c7a2dec92cf8f739e9e816a2119ed5a7b9285ad78a94fcb67334dee7523" )
  elseif( SYS_NAME STREQUAL "Darwin" AND SYS_PROC STREQUAL "arm64" )
    set( PELICAN_HASH "ba1c82c66abff4c56c85c714b0b08a13630adc223980939f377d43cc30714ded" )
  elseif( SYS_NAME STREQUAL "Linux" AND SYS_PROC STREQUAL "x86_64" )
    set( PELICAN_HASH "30d1cdbb5d18ff7dbb80e21f805666601d81a14579c5f10d6a153f80b818122a" )
  elseif( SYS_NAME STREQUAL "Linux" AND SYS_PROC STREQUAL "arm64" )
    set( PELICAN_HASH "03ce68ebf7ce5bbef35c6181988ccb63de2084536e7d5baa0d067651cfbbe726" )
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
      TIMEOUT 180
      ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};WRK_BIN=${GoWrk}"
      ATTACHED_FILES_ON_FAIL "${PELICAN_TEST_LOGS}")
endif()
