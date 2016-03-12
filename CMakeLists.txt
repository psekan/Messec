cmake_minimum_required(VERSION 3.3)
project(Messec)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(COMMON_FILES src/common/ipv4.cpp)

set(SOURCE_FILES_CLIENT ${COMMON_FILES} src/client/main.cpp src/client/clientManager.cpp)
add_executable(MessecClient ${SOURCE_FILES_CLIENT})

set(SOURCE_FILES_SERVER ${COMMON_FILES} src/server/main.cpp)
add_executable(MessecServer ${SOURCE_FILES_SERVER})

set(SOURCE_FILES_TESTS ${COMMON_FILES} src/tests/main.cpp)
add_executable(MessecTests ${SOURCE_FILES_TESTS})