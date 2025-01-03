
cmake_minimum_required( VERSION 3.16 )
project(tinyxml2)

include(ExternalProject)
set( TINYXML2_URL "${CMAKE_CURRENT_SOURCE_DIR}/tinyxml2-10.0.0.tar.gz" )
if( NOT EXISTS "${TINYXML2_URL}" )
    set( TINYXML2_URL "https://github.com/leethomason/tinyxml2/archive/refs/tags/10.0.0.tar.gz" )
endif()
cmake_policy(SET CMP0135 NEW)

# 3bdf15128ba16686e69bce256cc468e76c7b94ff2c7f391cc5ec09e40bff3839 is the GitHub source artifact
# corresponding to git tag v10.0.0
#
# Note we override CMAKE_INSTALL_LIBDIR to force it to be `lib`; on RHEL platforms, it defaults
# to lib64, messing up the CMAKE_PREFIX_PATH search for the cmake files.
ExternalProject_Add(
    tinyxml2
    URL "${TINYXML2_URL}"
    URL_HASH SHA256=3bdf15128ba16686e69bce256cc468e76c7b94ff2c7f391cc5ec09e40bff3839
    TEST_COMMAND ""
    CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>;-DCMAKE_INSTALL_LIBDIR=lib;-DCMAKE_POSITION_INDEPENDENT_CODE=ON" )

