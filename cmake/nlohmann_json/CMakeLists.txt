
cmake_minimum_required( VERSION 3.16 )
project(nlohmann_json)

include(ExternalProject)
# 9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03 is git tag v3.11.3
ExternalProject_Add(
    nlohmann_json
    URL https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz
    URL_HASH SHA256=0d8ef5af7f9794e3263480193c491549b2ba6cc74bb018906202ada498a79406
    TEST_COMMAND ""
    CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>;-DBUILD_TESTING=OFF;-DJSON_BuildTests=OFF" )

