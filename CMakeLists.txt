cmake_minimum_required(VERSION 3.10)
project(ruleprocessorY)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_DEBUG ON)


# Include boost libraries
find_package(Boost 1.71.0 COMPONENTS program_options REQUIRED)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ruleprocessorY main.cpp rule.h rule.cpp)
# Link boost
include_directories(${Boost_INCLUDE_DIRS})
target_link_libraries(ruleprocessorY LINK_PUBLIC ${Boost_LIBRARIES})
