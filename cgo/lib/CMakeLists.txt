cmake_minimum_required(VERSION 3.1)
set(CMAKE_BUILD_TYPE Release)

project(libtest C CXX)

include_directories(SYSTEM include)

file(GLOB testGlob src/*.cpp)
add_library(calc ${testGlob})
