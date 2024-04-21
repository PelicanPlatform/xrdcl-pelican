
cmake_minimum_required( VERSION 3.16 )
project( xrdcl-pelican )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

find_package( Xrootd REQUIRED )

if(NOT XROOTD_PLUGIN_VERSION)
  find_program(XROOTD_CONFIG_EXECUTABLE xrootd-config)
  exec_program(${XROOTD_CONFIG_EXECUTABLE} ARGS "--plugin-version" OUTPUT_VARIABLE XROOTD_PLUGIN_VERSION RETURN_VALUE RETVAR)
  set(XROOTD_PLUGIN_VERSION ${XROOTD_PLUGIN_VERSION} CACHE INTERNAL "")
endif()

set (CMAKE_CXX_STANDARD 14)

include (FindPkgConfig)
pkg_check_modules(LIBCRYPTO REQUIRED libcrypto)

find_package( CURL REQUIRED )
find_package( Threads REQUIRED )

option(ENABLE_TESTS "Enable unit tests" FALSE)
if (ENABLE_TESTS)
  find_package(GTest REQUIRED)
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

include_directories(${XROOTD_INCLUDES} ${CURL_INCLUDE_DIRS} vendor/)

add_library(XrdClPelican SHARED src/CurlUtil.cc src/CurlUtil.hh src/CurlOps.cc src/CurlOps.hh src/PelicanFactory.cc src/PelicanFile.cc src/PelicanFile.hh src/PelicanFilesystem.cc src/PelicanFilesystem.hh src/FedInfo.cc src/FedInfo.hh src/ParseTimeout.cc src/ParseTimeout.hh)
target_link_libraries(XrdClPelican ${XROOTD_UTILS_LIB} ${XROOTD_CLIENT_LIB} ${CURL_LIBRARIES} Threads::Threads)

if(APPLE)
  SET(LIBRARY_SUFFIX ".dylib")
  set_target_properties(XrdClPelican PROPERTIES OUTPUT_NAME "XrdClPelican-${XROOTD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX})
else()
  SET(LIBRARY_SUFFIX ".so")
  set_target_properties(XrdClPelican PROPERTIES OUTPUT_NAME "XrdClPelican-${XROOTD_PLUGIN_VERSION}" SUFFIX ${LIBRARY_SUFFIX} LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols")
endif()

SET(SYSCONF_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/etc" CACHE PATH "Install path for configuration files")
SET(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Install path for libraries")

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
