cmake_minimum_required(VERSION 3.10)
project(ProcessHollowing C)

set(CMAKE_C_STANDARD 11)

add_executable(process_hollowing
    process_hollowing.c
    pe.c
    pe.h
    internals.h
)

# 链接 Windows 库
target_link_libraries(process_hollowing dbghelp)
