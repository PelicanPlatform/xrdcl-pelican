
cmake_minimum_required( VERSION 3.19 )
project( xrdcl-pelican )

set( CMAKE_CXX_STANDARD 20 )

set( CMAKE_MODULE_PATH
  ${PROJECT_SOURCE_DIR}/cmake
)

option( ENABLE_ASAN "Enable address sanitizer." FALSE )
if( ENABLE_ASAN )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -fsanitize=address")
endif()

if( ENABLE_TSAN )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -fsanitize=thread")
endif()

find_package( XRootD REQUIRED COMPONENTS UTILS CLIENT )
find_package( CURL REQUIRED )
find_package( Threads REQUIRED )
find_package( OpenSSL REQUIRED )

option( ENABLE_TESTS "Enable unit tests" FALSE )
if( ENABLE_TESTS )
  if( NOT XROOTD_PLUGINS_EXTERNAL_GTEST )
    include( FetchContent )
    set( GTEST_URL "${CMAKE_CURRENT_SOURCE_DIR}/googletest-1.15.2.tar.gz" )
    if( NOT EXISTS "${GTEST_URL}" )
        set( GTEST_URL "https://github.com/google/googletest/releases/download/v1.15.2/googletest-1.15.2.tar.gz" )
    endif()
    cmake_policy(SET CMP0135 NEW)
    FetchContent_Declare(GTest
      URL "${GTEST_URL}"
      URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
      TEST_COMMAND ""
    )
    FetchContent_MakeAvailable( GTest )
  else()
    find_package( GTest REQUIRED )
  endif()

  # go-wrk is a simple HTTP load tester, useful for stress testing
  # The unit test using go-wrk have a small feature improvement over
  # upstream; try installing with:
  #   $ go install github.com/bbockelm/go-wrk@92dbe19
  #
  find_program(GoWrk go-wrk HINTS "$ENV{HOME}/go/bin")

  enable_testing()
  set(BUILD_TESTS TRUE)
else()
  set(BUILD_TESTS FALSE)
endif()

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()
if(NOT APPLE)
  SET( CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")
  SET( CMAKE_MODULE_LINKER_FLAGS "-Wl,--no-undefined")
endif()

if( NOT XROOTD_EXTERNAL_TINYXML2 )
  # This causes tinyxml2 to be downloaded and installed to the binary directory at configure time,
  # allowing this copy to be used in the find_package(tinyxml2) below
  if( NOT EXISTS "${CMAKE_BINARY_DIR}/tinyxml2/tinyxml2-prefix/lib/cmake/tinyxml2/tinyxml2-config.cmake" )
    file( MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tinyxml2 )
    execute_process(
      COMMAND ${CMAKE_COMMAND} ${CMAKE_SOURCE_DIR}/cmake/tinyxml2
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tinyxml2
      COMMAND_ERROR_IS_FATAL ANY )
    execute_process(
      COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/tinyxml2
      COMMAND_ERROR_IS_FATAL ANY )
  endif()
  list( APPEND CMAKE_PREFIX_PATH "${CMAKE_BINARY_DIR}/tinyxml2/tinyxml2-prefix/lib/cmake/tinyxml2" )
endif()
find_package(tinyxml2)

if( NOT XROOTD_EXTERNAL_JSON )
  if( NOT EXISTS "${CMAKE_BINARY_DIR}/nlohmann_json/nlohmann_json-prefix/share/cmake/nlohmann_json/nlohmann_jsonConfig.cmake" )
    file( MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/nlohmann_json )
    execute_process(
      COMMAND ${CMAKE_COMMAND} ${CMAKE_SOURCE_DIR}/cmake/nlohmann_json
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/nlohmann_json
      COMMAND_ERROR_IS_FATAL ANY )
    execute_process(
      COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/nlohmann_json
      COMMAND_ERROR_IS_FATAL ANY )
  endif()
  list( APPEND CMAKE_PREFIX_PATH "${CMAKE_BINARY_DIR}/nlohmann_json/nlohmann_json-prefix/share/cmake/nlohmann_json" )
endif()
find_package(nlohmann_json)

add_subdirectory(tests)

#
# The `XErrorCode::kXR_TimerExpired` error code was not added until 5.7.0
#
include(CheckSourceCompiles)
set( CMAKE_REQUIRED_INCLUDES "${XRootD_INCLUDE_DIR}" )
CHECK_SOURCE_COMPILES(CXX
"#include <XProtocol/XProtocol.hh>
int main(void) {if (XErrorCode::kXR_TimerExpired) {return 1;} return 0;}"
HAVE_XPROTOCOL_TIMEREXPIRED)

#
# Determine if we're using a 5.x-style or 6.x-style version of the XrdClPlugInInterface
#
CHECK_SOURCE_COMPILES(CXX
"#include <XrdCl/XrdClPlugInInterface.hh>
class File final : public XrdCl::FilePlugIn {
public:
    File() {}
    virtual ~File() noexcept {}
    virtual XrdCl::XRootDStatus Open(const std::string &, XrdCl::OpenFlags::Flags, XrdCl::Access::Mode, XrdCl::ResponseHandler *, time_t) override;
};
int main(void) {return 0;}"
HAVE_XRDCL_IFACE6)

#
# Generate a reasonable version string to use
#
if( NOT DEFINED XrdClCurl_VERSION_STRING )
  set( XrdClCurl_VERSION_STRING "devel" )
endif()

if( XrdClCurl_VERSION_STRING MATCHES "devel" AND IS_DIRECTORY ${PROJECT_SOURCE_DIR}/.git )
  find_package( Git QUIET )
  if( Git_FOUND )
    message( VERBOSE "Determining version with git" )
    execute_process( COMMAND
      ${GIT_EXECUTABLE} --git-dir ${PROJECT_SOURCE_DIR}/.git describe --tags
      OUTPUT_VARIABLE XrdClCurl_VERSION_STRING ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE )
    set( XrdClCurl_VERSION_STRING "${XrdClCurl_VERSION_STRING}" CACHE INTERNAL "XrdClCurl version" )
  endif()
endif()

#
# Generate the correct version information
#
configure_file(src/XrdClCurl/XrdClCurlVersion.hh.in src/XrdClCurl/XrdClCurlVersion.hh)

add_library(XrdClPelicanObj OBJECT
  src/common/XrdClCurlResponseInfo.hh              src/common/XrdClCurlResponses.hh
  src/common/XrdClCurlParseTimeout.cc              src/common/XrdClCurlParseTimeout.hh
  src/XrdClPelican/BrokerCache.cc                  src/XrdClPelican/BrokerCache.hh
  src/XrdClPelican/ChecksumCache.cc
  src/XrdClPelican/ConnectionBroker.cc             src/XrdClPelican/ConnectionBroker.hh
  src/XrdClPelican/DirectorCache.cc                src/XrdClPelican/DirectorCache.hh
  src/XrdClPelican/DirectorCacheResponseHandler.cc src/XrdClPelican/DirectorCacheResponseHandler.hh
  src/XrdClPelican/FedInfo.cc                      src/XrdClPelican/FedInfo.hh
  src/XrdClPelican/PelicanFactory.cc               src/XrdClPelican/PelicanFactory.hh
  src/XrdClPelican/PelicanFile.cc                  src/XrdClPelican/PelicanFile.hh
  src/XrdClPelican/PelicanFilesystem.cc            src/XrdClPelican/PelicanFilesystem.hh
  src/XrdClPelican/PelicanHeaders.cc               src/XrdClPelican/PelicanHeaders.hh
)
target_include_directories( XrdClPelicanObj PUBLIC ${PROJECT_BINARY_DIR}/src )

add_library(XrdClCurlObj OBJECT
  src/common/XrdClCurlParseTimeout.cc    src/common/XrdClCurlParseTimeout.hh
  src/common/XrdClCurlResponseInfo.hh
  src/common/XrdClCurlResponses.hh
  src/XrdClCurl/XrdClCurlFactory.cc      src/XrdClCurl/XrdClCurlFactory.hh
  src/XrdClCurl/XrdClCurlFile.cc         src/XrdClCurl/XrdClCurlFile.hh
  src/XrdClCurl/XrdClCurlFilesystem.cc   src/XrdClCurl/XrdClCurlFilesystem.hh
  src/XrdClCurl/XrdClCurlOpChecksum.cc
  src/XrdClCurl/XrdClCurlOpCopy.cc
  src/XrdClCurl/XrdClCurlOpDelete.cc
  src/XrdClCurl/XrdClCurlOpListdir.cc
  src/XrdClCurl/XrdClCurlOpMkcol.cc
  src/XrdClCurl/XrdClCurlOpOpen.cc
  src/XrdClCurl/XrdClCurlOpOptions.cc
  src/XrdClCurl/XrdClCurlOpPut.cc
  src/XrdClCurl/XrdClCurlOpQuery.cc
  src/XrdClCurl/XrdClCurlOpRead.cc
  src/XrdClCurl/XrdClCurlOpReadV.cc
  src/XrdClCurl/XrdClCurlOpStat.cc
  src/XrdClCurl/XrdClCurlOps.cc          src/XrdClCurl/XrdClCurlOps.hh
  src/XrdClCurl/XrdClCurlOptionsCache.cc src/XrdClCurl/XrdClCurlOptionsCache.hh
  src/XrdClCurl/XrdClCurlUtil.cc         src/XrdClCurl/XrdClCurlUtil.hh
)
# Makes the generated XrdClCurlVersion.hh in the include path
target_include_directories( XrdClCurlObj PUBLIC ${PROJECT_BINARY_DIR}/src/XrdClCurl )

add_library( XrdClS3Obj OBJECT
  src/XrdClS3/XrdClS3DownloadHandler.cc src/XrdClS3/XrdClS3DownloadHandler.hh
  src/XrdClS3/XrdClS3Factory.cc         src/XrdClS3/XrdClS3Factory.hh
  src/XrdClS3/XrdClS3File.cc            src/XrdClS3/XrdClS3File.hh
  src/XrdClS3/XrdClS3Filesystem.cc      src/XrdClS3/XrdClS3Filesystem.hh
)

target_link_libraries( XrdClPelicanObj XRootD::XrdCl XRootD::XrdUtils CURL::libcurl tinyxml2::tinyxml2 Threads::Threads nlohmann_json::nlohmann_json OpenSSL::Crypto )
target_link_libraries( XrdClCurlObj XRootD::XrdCl XRootD::XrdUtils XRootD::XrdServer CURL::libcurl tinyxml2::tinyxml2 Threads::Threads nlohmann_json::nlohmann_json OpenSSL::Crypto )
target_link_libraries( XrdClS3Obj XRootD::XrdCl XRootD::XrdUtils tinyxml2::tinyxml2 Threads::Threads OpenSSL::Crypto )
set_target_properties( XrdClPelicanObj PROPERTIES POSITION_INDEPENDENT_CODE ON )
set_target_properties( XrdClCurlObj PROPERTIES POSITION_INDEPENDENT_CODE ON )
set_target_properties( XrdClS3Obj PROPERTIES POSITION_INDEPENDENT_CODE ON )

if (HAVE_XPROTOCOL_TIMEREXPIRED)
  target_compile_definitions(XrdClPelicanObj PUBLIC HAVE_XPROTOCOL_TIMEREXPIRED)
  target_compile_definitions(XrdClCurlObj PUBLIC HAVE_XPROTOCOL_TIMEREXPIRED)
endif()
if (HAVE_XRDCL_IFACE6)
  target_compile_definitions(XrdClPelicanObj PUBLIC HAVE_XRDCL_IFACE6)
  target_compile_definitions(XrdClCurlObj PUBLIC HAVE_XRDCL_IFACE6)
endif()

# The test executables cannot link against the normal library on Linux as we hide the exported symbols
if (ENABLE_TESTS)
  add_library(XrdClPelicanTesting SHARED "$<TARGET_OBJECTS:XrdClPelicanObj>")
  target_link_libraries(XrdClPelicanTesting XrdClPelicanObj)
  target_include_directories(XrdClPelicanTesting PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

  add_library(XrdClCurlTesting SHARED "$<TARGET_OBJECTS:XrdClCurlObj>")
  target_link_libraries(XrdClCurlTesting XrdClCurlObj)
  target_include_directories(XrdClCurlTesting PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

  add_library( XrdClS3Testing SHARED "$<TARGET_OBJECTS:XrdClS3Obj>" )
  target_link_libraries( XrdClS3Testing XrdClS3Obj )
  target_include_directories( XrdClS3Testing PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src )
endif()

add_library(XrdClPelican MODULE "$<TARGET_OBJECTS:XrdClPelicanObj>")
target_link_libraries(XrdClPelican XrdClPelicanObj)

add_library(XrdClCurl MODULE "$<TARGET_OBJECTS:XrdClCurlObj>")
target_link_libraries(XrdClCurl XrdClCurlObj)

add_library( XrdClS3 MODULE "$<TARGET_OBJECTS:XrdClS3Obj>" )
target_link_libraries( XrdClS3 XrdClS3Obj )

if(APPLE)
  SET(LIBRARY_SUFFIX ".dylib")
  set_target_properties(XrdClPelican PROPERTIES OUTPUT_NAME "XrdClPelican-${XRootD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX})
  set_target_properties(XrdClCurl PROPERTIES OUTPUT_NAME "XrdClCurl-${XRootD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX})
  set_target_properties( XrdClS3 PROPERTIES OUTPUT_NAME "XrdClS3-${XRootD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX} )
else()
  SET(LIBRARY_SUFFIX ".so")
  set_target_properties(XrdClPelican PROPERTIES OUTPUT_NAME "XrdClPelican-${XRootD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX} LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols")
  set_target_properties(XrdClCurl PROPERTIES OUTPUT_NAME "XrdClCurl-${XRootD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX} LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols")
  set_target_properties( XrdClS3 PROPERTIES OUTPUT_NAME "XrdClS3-${XRootD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX} LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols" )
endif()

SET( SYSCONF_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/etc" CACHE PATH "Install path for configuration files" )
SET( LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Install path for libraries" )

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/configs/pelican-plugin.conf ${CMAKE_CURRENT_BINARY_DIR}/configs/pelican-plugin.conf)
configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/configs/curl-plugin.conf ${CMAKE_CURRENT_BINARY_DIR}/configs/curl-plugin.conf)
configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/configs/s3-plugin.conf ${CMAKE_CURRENT_BINARY_DIR}/configs/s3-plugin.conf )

install(
  TARGETS XrdClPelican XrdClCurl XrdClS3
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/configs/pelican-plugin.conf ${CMAKE_CURRENT_BINARY_DIR}/configs/curl-plugin.conf ${CMAKE_CURRENT_BINARY_DIR}/configs/s3-plugin.conf
  DESTINATION ${SYSCONF_INSTALL_DIR}/xrootd/client.plugins.d/
)
