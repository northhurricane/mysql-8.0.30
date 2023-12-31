cmake_minimum_required(VERSION 2.8)
CMAKE_policy(SET CMP0015 NEW)
project(cos-cpp-sdk)
set(CMAKE_VERBOSE_MAKEFILE  ON)

option(BUILD_UNITTEST "Build unittest" OFF)
option(BUILD_DEMO "Build demo" ON)
option(BUILD_SHARED_LIB "Build shared library" ON)

SET(COS_SOURCE_DIR
  "${CMAKE_SOURCE_DIR}/extra/cos")

if(APPLE)
    set(OS_TYPE "APPLE")
elseif(UNIX)
    set(OS_TYPE "LINUX")
elseif(WIN32)
    set(OS_TYPE "WINDOWS")
else()
    message(FATAL_ERROR "unkonwn os type")
endif()
message(STATUS "OS type: ${OS_TYPE}")

if (${OS_TYPE} STREQUAL "WINDOWS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    set(BUILD_TARGET "Win32")
    if (CMAKE_CL_64)
        set(BUILD_TARGET "x64")
    endif()
    message(STATUS "Build target: ${BUILD_TARGET}")
    if (NOT DEFINED ${CMAKE_BUILD_TYPE})
        set(CMAKE_BUILD_TYPE "Release")
    endif()
    message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

    set(POCO_LINK_DIR ${COS_SOURCE_DIR}/third_party/lib/${BUILD_TARGET}/poco)
    set(POCO_INCLUDE_DIR ${COS_SOURCE_DIR}/third_party/include/)
    set(POCO_LIBS PocoNetSSL PocoNet PocoCrypto PocoUtil PocoJSON PocoFoundation PocoXML)

    set(SYSTEM_LIBS "")
    #需要加该参数，不然VS会报错
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
else()
    set(POCO_LINK_DIR ${COS_SOURCE_DIR}/third_party/lib/linux/poco/)
    # if (${OS_TYPE} STREQUAL "APPLE")
    #     set(POCO_LINK_DIR ${COS_SOURCE_DIR}/third_party/lib/macOS/poco/)
    #     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra")
    # else()
    #     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra")
    # endif()
        set(POCO_INCLUDE_DIR ${COS_SOURCE_DIR}/third_party/include/)
    set(POCO_LIBS PocoNetSSL PocoNet PocoCrypto PocoUtil PocoJSON PocoFoundation PocoXML)

    set(SYSTEM_LIBS stdc++ pthread)
endif()

add_subdirectory(src)

if(BUILD_UNITTEST)
    message(STATUS "Build unittest")

    set(GTEST_INCLUDE_DIR ${COS_SOURCE_DIR}/third_party/include/gtest/)
    set(GTEST_LINK_DIR ${COS_SOURCE_DIR}/third_party/lib/linux/gtest/)
    if (${OS_TYPE} STREQUAL "WINDOWS")
        set(GTEST_LINK_DIR  ${COS_SOURCE_DIR}/third_party/lib/${BUILD_TARGET}/gtest)
    endif()
    set(GTEST_LIBS gtest gtest_main)

    set(UT_INCLUDE_DIR ${COS_SOURCE_DIR}/unittest/include/)

    # add_subdirectory(unittest)
endif()

if(BUILD_DEMO)
    message(STATUS "Build demo")
    add_subdirectory(demo)
endif()