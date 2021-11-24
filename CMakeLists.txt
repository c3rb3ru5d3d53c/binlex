cmake_minimum_required(VERSION 3.16.3)

project(binlex)

add_executable(${PROJECT_NAME} main.cpp)

# This is a hack (remove this later)
#set(CMAKE_CXX_FLAGS "-fpermissive")

target_link_libraries(${PROJECT_NAME} -lcapstone -lcrypto -lm)
