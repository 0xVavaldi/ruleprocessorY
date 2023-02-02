cmake_minimum_required(VERSION 3.10)
project(ruleprocessorY)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
add_executable(ruleprocessorY main.cpp rule.h rule.cpp)
target_link_libraries(ruleprocessorY ${CMAKE_THREAD_LIBS_INIT})
