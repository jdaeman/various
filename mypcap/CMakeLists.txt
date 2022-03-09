cmake_minimum_required(VERSION 3.1)
set(CMAKE_BUILD_TYPE Release)

project(mypcap C CXX)

enable_testing()
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

if (GTest_FOUND)
message(STATUS "[GTEST include] " ${GTEST_INCLUDE_DIRS})
message(STATUS "[GTEST lib] " ${GTEST_LIBRARIES})
else ()
message(FATAL_ERROR "Could not find googletest")
endif ()


include_directories(AFTER ${GTEST_INCLUDE_DIRS})

add_executable(simple-test src/tests/simple_test.cpp)
# target_link_libraries(simple-test ${CMAKE_THREAD_LIBS_INIT} ${GTEST_LIBRARIES})
# import ordering...
target_link_libraries(simple-test ${GTEST_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

