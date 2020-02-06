# CMakeFiles for 3rd vendor library

include(ExternalProject)



include(ExternalProject)

### OpenSSL 1.1.1
ExternalProject_Add(OpenSSL PREFIX openssl
        URL ${CMAKE_CURRENT_SOURCE_DIR}/openssl-1.1.1.tar.gz
        URL_MD5 d65944e4aa4de6ad9858e02c82d85183
        CONFIGURE_COMMAND ./Configure enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers linux-x86_64 --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR>/lib/ssl
							enable-ec_nistp_64_gcc_128 no-shared
		BUILD_COMMAND ${MAKE_COMMAND}
		INSTALL_COMMAND make install_sw
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(OpenSSL INSTALL_DIR)
set(OPENSSL_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set(OPENSSL_LINK_DIRECTORIES ${INSTALL_DIR}/lib)
set(OPENSSL_PKGCONFIG_PATH ${INSTALL_DIR}/lib/pkgconfig/)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(openssl-crypto-static STATIC IMPORTED GLOBAL)
add_dependencies(openssl-crypto-static OpenSSL)
set_property(TARGET openssl-crypto-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libcrypto.a)
set_property(TARGET openssl-crypto-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

add_library(openssl-ssl-static STATIC IMPORTED GLOBAL)
add_dependencies(openssl-ssl-static OpenSSL)
set_property(TARGET openssl-ssl-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libssl.a)
set_property(TARGET openssl-ssl-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)


### cJSON: 注意: -DCMAKE_POSITION_INDEPENDENT_CODE=ON
ExternalProject_Add(cJSON PREFIX cJSON
        URL ${CMAKE_CURRENT_SOURCE_DIR}/cJSON-1.7.7.tar.gz
        URL_MD5 715009c99728bf81d6c97352718650ff
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
				   -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                                   -DCMAKE_POSITION_INDEPENDENT_CODE=ON
				   -DBUILD_SHARED_AND_STATIC_LIBS=1)

ExternalProject_Get_Property(cJSON INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(cjson SHARED IMPORTED GLOBAL)
add_dependencies(cjson cJSON)
set_property(TARGET cjson PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/libcjson.a)
set_property(TARGET cjson PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

### MESA Framework
set(MESA_FRAMEWORK_LIB_DIR /opt/MESA/lib)
set(MESA_FRAMEWORK_INCLUDE_DIR /opt/MESA/include)

add_library(MESA_handle_logger SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_handle_logger PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_handle_logger.so)
set_property(TARGET MESA_handle_logger PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(MESA_prof_load SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_prof_load PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_prof_load.so)
set_property(TARGET MESA_prof_load PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(wiredcfg SHARED IMPORTED GLOBAL)
set_property(TARGET wiredcfg PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libwiredcfg.so)
set_property(TARGET wiredcfg PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(MESA_htable SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_htable PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_htable.so)
set_property(TARGET MESA_htable PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(maatframe SHARED IMPORTED GLOBAL)
set_property(TARGET maatframe PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libmaatframe.so)
set_property(TARGET maatframe PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(MESA_field_stat SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_field_stat PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_field_stat2.so)
set_property(TARGET MESA_field_stat PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(rdkafka SHARED IMPORTED GLOBAL)
set_property(TARGET rdkafka PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/librdkafka.so)
set_property(TARGET rdkafka PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})