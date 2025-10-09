cmake_minimum_required(VERSION 3.10)

project(RedirectThread)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add AlertableThreadsForDays executable
add_executable(AlertableThreadsForDays
    AlertableThreadsForDays/AlertableThreadsForDays.cpp
)

# Add RedirectThread executable
add_executable(RedirectThread
    RedirectThread/Arguments.cpp
    RedirectThread/GadgetUtil.cpp
    RedirectThread/Injection.cpp
    RedirectThread/main.cpp
    RedirectThread/NativeAPI.cpp
    RedirectThread/NtCreateThreadUtil.cpp
    RedirectThread/ProcessThread.cpp
    RedirectThread/APCInjection.cpp
    RedirectThread/CreateRemoteThreadUtil.cpp
    RedirectThread/DLLInjection.cpp
    RedirectThread/Helpers.cpp
)

# Add include directories if necessary, for example:
# target_include_directories(RedirectThread PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/RedirectThread)
# target_include_directories(AlertableThreadsForDays PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/AlertableThreadsForDays)

# Add link libraries if necessary, for example:
# target_link_libraries(RedirectThread PRIVATE some_library)

# Optional: Set output directory for executables
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
