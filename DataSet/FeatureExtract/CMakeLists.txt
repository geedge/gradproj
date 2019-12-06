cmake_minimum_required(VERSION 3.5)
project(kni)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set (CMAKE_CXX_FLAGS "-Wall")
#set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lasan -fsanitize-recover=address -fsanitize=address -fno-omit-frame-pointer")

add_definitions(-D_GNU_SOURCE)

if (CMAKE_BUILD_TYPE STREQUAL Debug) 
    add_definitions(-DDEBUG)
endif()

add_subdirectory(vendor)
add_subdirectory(entry)

# cmake -DCMAKE_BUILD_TYPE=Debug/RelWithDebInfo