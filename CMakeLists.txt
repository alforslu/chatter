cmake_minimum_required(VERSION 4.0) # Probably works on earlier but I am not testing it
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(chat)

# c++23 required
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Includes
include_directories(${PROJECT_SOURCE_DIR}/include)

# Library cpp files
add_library(chat
    src/server.cc
)

add_executable(chatter src/main.cc)
target_link_libraries(chatter PRIVATE chat)
