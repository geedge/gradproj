add_library(stmstat SHARED src/stmstat_entry.cpp src/ssl_utils.cpp)
target_include_directories(stmstat PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(stmstat MESA_prof_load MESA_field_stat cjson)


add_library(sslstat SHARED src/sslstat_entry.cpp)
target_include_directories(sslstat PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(sslstat MESA_prof_load MESA_field_stat cjson)

add_library(sslparse SHARED src/sslparse_entry.cpp src/ssl_utils.cpp src/base64.cpp)
target_include_directories(sslparse PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(sslparse MESA_prof_load MESA_field_stat cjson)

add_executable(test_base64 src/base64.cpp)
target_include_directories(test_base64 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)
