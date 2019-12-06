add_library(stmstat SHARED src/tcp_entry.cpp src/ssl_utils.cpp)
target_include_directories(stmstat PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(stmstat MESA_prof_load MESA_field_stat cjson)