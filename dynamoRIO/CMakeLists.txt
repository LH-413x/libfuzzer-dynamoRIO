cmake_minimum_required(VERSION 2.8)
project(blackBoxFuzzer_DynamoRIO)

if ("${CMAKE_VERSION}" VERSION_EQUAL "3.0" OR
        "${CMAKE_VERSION}" VERSION_GREATER "3.0")
    cmake_policy(SET CMP0026 OLD)
endif ()

set(CMAKE_CXX_STANDARD 11)
set(DynamoRIO_DIR DynamoRIO-Linux-7.1.0-1/cmake)
set(DrMemoryFramework_DIR DynamoRIO-Linux-7.1.0-1/drmemory/drmf)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

find_package(DrMemoryFramework)
if (NOT DrMemoryFramework_FOUND)
    message(FATAL_ERROR "DrMemoryFramework page required to build")
endif(NOT DrMemoryFramework_FOUND)


#set(libtype STATIC)
set(libtype SHARED)
#endif ()

add_library(drtrace SHARED
        drtracelib.cpp
        )

include_directories(${PROJECT_SOURCE_DIR}/hongg_instrument)

configure_DynamoRIO_client(drtrace)
use_DynamoRIO_extension(drtrace drmgr)
use_DynamoRIO_extension(drtrace drx)
use_DynamoRIO_extension(drtrace drcontainers)
use_DynamoRIO_extension(drtrace drreg)
use_DynamoRIO_extension(drtrace drwrap)
use_DynamoRIO_extension(drtrace drsyms)

TARGET_LINK_LIBRARIES(drtrace pthread)
