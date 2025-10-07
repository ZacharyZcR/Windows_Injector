cmake_minimum_required(VERSION 3.10)
project(EntryPointInjection C)

set(CMAKE_C_STANDARD 11)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Shellcode 生成器
add_executable(generate_shellcode
    src/generate_shellcode.c
)

# 测试载荷
add_executable(test_payload
    src/test_payload.c
)

target_link_libraries(test_payload
    user32
)

# Entry Point Injection 主程序
add_executable(entry_point_injection
    src/entry_point_injection.c
)

# 链接必要的库
target_link_libraries(entry_point_injection
    ntdll
)

# 编译选项
if(MSVC)
    target_compile_options(entry_point_injection PRIVATE /W4)
    target_compile_options(generate_shellcode PRIVATE /W4)
    target_compile_options(test_payload PRIVATE /W4)
else()
    target_compile_options(entry_point_injection PRIVATE -Wall -Wextra -O2)
    target_compile_options(generate_shellcode PRIVATE -Wall -Wextra -O2)
    target_compile_options(test_payload PRIVATE -Wall -Wextra -O2)
endif()

# 自定义命令：生成 payload.bin
add_custom_command(
    OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/payload.bin
    COMMAND generate_shellcode ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/payload.bin
    DEPENDS generate_shellcode
    COMMENT "Generating shellcode payload..."
)

# 自定义目标：确保在构建时生成 payload
add_custom_target(generate_payload ALL
    DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/payload.bin
)

# 打印构建信息
message(STATUS "Building Entry Point Injection")
message(STATUS "Architecture: ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID}")
