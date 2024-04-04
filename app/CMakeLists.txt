project (password_manager C)

set(SRC host/main.c host/tee.c host/ui.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ${CMAKE_SOURCE_DIR}/ta/include
			   PRIVATE ${CMAKE_SOURCE_DIR}/host/include
			   PRIVATE ${CMAKE_SOURCE_DIR}/include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
