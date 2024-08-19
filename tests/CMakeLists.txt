
if (NOT BUILD_TESTS)
  return()
endif()

include(GoogleTest)

add_executable(xrdcl-pelican-test DirectorCacheTest.cc)
target_include_directories(xrdcl-pelican-test PRIVATE ../src)

target_link_libraries(xrdcl-pelican-test XrdClPelican GTest::GTest GTest::Main)

gtest_discover_tests(xrdcl-pelican-test)

