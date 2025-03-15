
cmake_minimum_required( VERSION 3.19 )
project( xrdcl-pelican )

set( CMAKE_CXX_STANDARD 20 )

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
add_subdirectory(tests)

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

add_library(XrdClPelicanObj OBJECT
  src/ChecksumCache.cc
  src/CurlChecksum.cc
  src/CurlUtil.cc src/CurlUtil.hh
  src/CurlListdir.cc
  src/CurlOps.cc src/CurlOps.hh
  src/PelicanFactory.cc src/PelicanFactory.hh
  src/PelicanFile.cc src/PelicanFile.hh
  src/PelicanFilesystem.cc src/PelicanFilesystem.hh
  src/FedInfo.cc src/FedInfo.hh
  src/ParseTimeout.cc src/ParseTimeout.hh
  src/DirectorCache.cc src/DirectorCache.hh
)
target_include_directories(XrdClPelicanObj PRIVATE ${XRootD_INCLUDE_DIR})
target_link_libraries( XrdClPelicanObj ${XRootD_UTILS_LIBRARIES} ${XRootD_CLIENT_LIBRARIES} CURL::libcurl tinyxml2::tinyxml2 Threads::Threads nlohmann_json::nlohmann_json OpenSSL::Crypto )
set_target_properties(XrdClPelicanObj PROPERTIES POSITION_INDEPENDENT_CODE ON)
if (HAVE_XPROTOCOL_TIMEREXPIRED)
  target_compile_definitions(XrdClPelicanObj PUBLIC HAVE_XPROTOCOL_TIMEREXPIRED)
endif()
if (HAVE_XRDCL_IFACE6)
  target_compile_definitions(XrdClPelicanObj PUBLIC HAVE_XRDCL_IFACE6)
endif()

# The test executables cannot link against the normal library on Linux as we hide the exported symbols
if (ENABLE_TESTS)
  add_library(XrdClPelicanTesting SHARED "$<TARGET_OBJECTS:XrdClPelicanObj>")
  target_link_libraries(XrdClPelicanTesting XrdClPelicanObj)
endif()
add_library(XrdClPelican MODULE "$<TARGET_OBJECTS:XrdClPelicanObj>")
target_link_libraries(XrdClPelican XrdClPelicanObj)

if(APPLE)
  SET(LIBRARY_SUFFIX ".dylib")
  set_target_properties(XrdClPelican PROPERTIES OUTPUT_NAME "XrdClPelican-${XRootD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX})
else()
  SET(LIBRARY_SUFFIX ".so")
  set_target_properties(XrdClPelican PROPERTIES OUTPUT_NAME "XrdClPelican-${XRootD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX} LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols")
endif()

SET( SYSCONF_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/etc" CACHE PATH "Install path for configuration files" )
SET( LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Install path for libraries" )

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/configs/pelican-plugin.conf ${CMAKE_CURRENT_BINARY_DIR}/configs/pelican-plugin.conf)
configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/configs/pelican-plugin-http.conf ${CMAKE_CURRENT_BINARY_DIR}/configs/pelican-plugin-http.conf)

install(
  TARGETS XrdClPelican
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/configs/pelican-plugin.conf ${CMAKE_CURRENT_BINARY_DIR}/configs/pelican-plugin-http.conf
  DESTINATION ${SYSCONF_INSTALL_DIR}/xrootd/client.plugins.d/
)
