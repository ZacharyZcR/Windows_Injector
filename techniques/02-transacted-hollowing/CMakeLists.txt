cmake_minimum_required(VERSION 3.10)
project(TransactedHollowing C)

set(CMAKE_C_STANDARD 11)

# 主程序
add_executable(transacted_hollowing
    src/transacted_hollowing.c
    src/pe_utils.c
    src/pe_utils.h
    src/internals.h
)

# 链接必要的库
target_link_libraries(transacted_hollowing
    ktmw32    # Kernel Transaction Manager
    ntdll     # NT 函数
)

# 测试载荷
add_executable(test_payload
    src/test_payload.c
)

# 设置 Unicode
set_target_properties(transacted_hollowing PROPERTIES
    COMPILE_DEFINITIONS UNICODE
)
