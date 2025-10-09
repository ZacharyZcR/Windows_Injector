cmake_minimum_required (VERSION 3.10)

project ( waiting_thread_hijacking )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

option( SPLIT_STEPS "Split actions between different processes" OFF )

if(SPLIT_STEPS)
	add_compile_definitions(SPLIT_STEPS)
endif()

set (srcs
	threads_util.cpp
	hijacking.cpp
)

set (hdrs
	shellcode.h
	ntdll_api.h
	common.h
	threads_util.h
	hijacking.h
	ntddk.h
)

if(SPLIT_STEPS)
	set (srcs
		${srcs}
		main_split.cpp
	)
else()
	set (srcs
		${srcs}
		main.cpp
	)
endif()

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc})

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
