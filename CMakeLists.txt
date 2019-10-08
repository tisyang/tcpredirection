cmake_minimum_required(VERSION 2.8)
project(tcpredirection)
set(CMAKE_C_STANDARD 99)

add_subdirectory(wsocket)
add_subdirectory(ulog)

add_executable(${PROJECT_NAME} tcpredirection.c)
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS_RELEASE -s)
target_link_libraries(${PROJECT_NAME}
	wsocket
	ulog
	ev
)

