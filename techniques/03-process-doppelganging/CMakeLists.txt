cmake_minimum_required(VERSION 3.10)
project(ProcessDoppelganging C)

set(CMAKE_C_STANDARD 11)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 测试载荷
add_executable(test_payload
    src/test_payload.c
)

target_link_libraries(test_payload
    user32
)

# Process Doppelgänging 主程序
add_executable(process_doppelganging
    src/process_doppelganging.c
    src/pe_utils.c
    src/pe_utils.h
    src/internals.h
)

# 定义 Unicode 宏
target_compile_definitions(process_doppelganging PRIVATE
    UNICODE
    _UNICODE
)

# 链接必要的库
target_link_libraries(process_doppelganging
    ntdll      # NT API 函数
    ktmw32     # 事务管理
    userenv    # 环境块
)

# 编译选项
if(MSVC)
    target_compile_options(process_doppelganging PRIVATE /W4)
    target_compile_options(test_payload PRIVATE /W4)
else()
    target_compile_options(process_doppelganging PRIVATE -Wall -Wextra -O2)
    target_compile_options(test_payload PRIVATE -Wall -Wextra -O2)
endif()

# 打印构建信息
message(STATUS "Building Process Doppelgänging Technique")
message(STATUS "Architecture: ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID}")
