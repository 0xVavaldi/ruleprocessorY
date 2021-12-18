cmake_minimum_required(VERSION 3.10)
project(ruleprocessorY)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ruleprocessorY main.cpp rule.h rule.cpp)
