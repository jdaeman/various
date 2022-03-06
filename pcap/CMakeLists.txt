cmake_minimum_required(VERSION 3.1)
set(CMAKE_BUILD_TYPE Release)

if (WIN32)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
set(PCAP_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/WpdPack")
else ()
set(CMAKE_CXX_STANDARD 14)
endif ()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
project(pcaps C CXX)

find_package(PCAP REQUIRED)
find_package(Threads REQUIRED)

message(STATUS "pcap include " ${PCAP_INCLUDE_DIR})
message(STATUS "pcap lib " ${PCAP_LIBRARY})
message(STATUS "thread " ${CMAKE_THREAD_LIBS_INIT})

include_directories(SYSTEM ${PCAP_INCLUDE_DIR})

if (WIN32)
add_executable(findalldevs_ex src/pcap_findalldevs_ex.cpp)
target_compile_definitions(findalldevs_ex PUBLIC HAVE_REMOTE)
target_link_libraries(findalldevs_ex ${PCAP_LIBRARY})
target_link_libraries(findalldevs_ex ws2_32.lib)
endif()


add_executable(findalldevs src/pcap_findalldevs.cpp)
target_link_libraries(findalldevs ${PCAP_LIBRARY})
if (WIN32)
target_link_libraries(findalldevs ws2_32.lib)
endif()

add_executable(lookupnet src/pcap_lookupnet.cpp)
target_link_libraries(lookupnet ${PCAP_LIBRARY})
if (WIN32)
target_link_libraries(lookupnet ws2_32.lib)
endif()

add_executable(openlive src/pcap_open_live.cpp)
target_link_libraries(openlive ${PCAP_LIBRARY})
if (WIN32)
target_link_libraries(openlive ws2_32.lib)
endif()
