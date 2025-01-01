
cmake_minimum_required( VERSION 3.16 )
project(tinyxml2)

include(ExternalProject)
# 321ea883b7190d4e85cae5512a12e5eaa8f8731f is git tag v10.0.0
ExternalProject_Add(
    tinyxml2
    GIT_REPOSITORY https://github.com/leethomason/tinyxml2.git
    GIT_TAG 321ea883b7190d4e85cae5512a12e5eaa8f8731f
    TEST_COMMAND ""
    CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>;-DCMAKE_POSITION_INDEPENDENT_CODE=ON" )

