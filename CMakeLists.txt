cmake_minimum_required(VERSION 3.3)
project(Messec)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES_CLIENT src/client/main.cpp)
add_executable(MessecClient ${SOURCE_FILES_CLIENT})

set(SOURCE_FILES_SERVER src/server/main.cpp)
add_executable(MessecServer ${SOURCE_FILES_SERVER})

set(SOURCE_FILES_TESTS src/tests/main.cpp)
add_executable(MessecTests ${SOURCE_FILES_TESTS})