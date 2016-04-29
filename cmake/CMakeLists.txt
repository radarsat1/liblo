cmake_minimum_required(VERSION 3.0)

include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckLibraryExists)
include(TestBigEndian)
include(GNUInstallDirs)

set(PROJECT liblo)
project(${PROJECT})

set(PACKAGE_NAME "${PROJECT}")

if(NOT CMAKE_VERSION VERSION_LESS 3.1.0)
    set_property(TARGET ${LIBRARY} PROPERTY C_STANDARD 11)
    set_property(TARGET ${LIBRARY} PROPERTY CXX_STANDARD 11)
endif()

set(CMAKE_VERBOSE_MAKEFILE OFF)

set(LIBRARY_SHARED lo_shared)
set(LIBRARY_STATIC lo_static)
set(OSCDUMP oscdump)
set(OSCSEND oscsend)

set(LIBRARY_SOURCES
    ../src/address.c
    ../src/blob.c
    ../src/bundle.c
    ../src/message.c
    ../src/method.c
    ../src/pattern_match.c
    ../src/send.c
    ../src/server.c
    ../src/timetag.c
    ../src/version.c
    )

set(LIBRARY_HEADERS
    ../lo/lo_cpp.h
    ../lo/lo_errors.h
    ../lo/lo_lowlevel.h
    ../lo/lo_macros.h
    ../lo/lo_osc_types.h
    ../lo/lo_serverthread.h
    ../lo/lo_throw.h
    ../lo/lo_types.h
    ${CMAKE_CURRENT_BINARY_DIR}/lo/lo_endian.h
    ${CMAKE_CURRENT_BINARY_DIR}/lo/lo.h
    )

set(OSCDUMP_SOURCES ../src/tools/oscdump.c)
set(OSCSEND_SOURCES ../src/tools/oscsend.c)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    list(APPEND LIBRARY_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/src/liblo.def)
endif()

check_symbol_exists(poll poll.h HAVE_POLL)
check_symbol_exists(select sys/select.h HAVE_SELECT)
check_symbol_exists(getifaddrs sys/types.h ifaddrs.h HAVE_GETIFADDRS)
check_symbol_exists(inet_pton arpa/inet.h HAVE_INET_PTON)

set(THREADING ON CACHE BOOL "Build with threading support.")
if(THREADING)
    set(LIBRARY_SOURCES ${LIBRARY_SOURCES} ../src/server_thread.c)
endif()

set(BUILD_LANGUAGE C CACHE STRING "Build language (C or CXX)")
mark_as_advanced(BUILD_LANGUAGE)
set_source_files_properties(
    ${LIBRARY_SOURCES} ${OSCDUMP_SOURCES} ${OSCSEND_SOURCES}
    PROPERTIES LANGUAGE ${BUILD_LANGUAGE})

add_library(${LIBRARY_STATIC} STATIC ${LIBRARY_SOURCES})
add_library(${LIBRARY_SHARED} SHARED ${LIBRARY_SOURCES})
add_executable(${OSCDUMP} ${OSCDUMP_SOURCES})
add_executable(${OSCSEND} ${OSCSEND_SOURCES})

if(THREADING)
    set(ENABLE_THREADS 1)
    check_include_files(pthread.h HAVE_LIBPTHREAD)

    include(FindThreads)
    set(CMAKE_THREAD_PREFER_PTHREAD ON)
    find_package(Threads)

    target_link_libraries(${LIBRARY_SHARED} Threads::Threads)

    set(THREADS_INCLUDE
      "#include \"lo/lo_serverthread.h\"")

else()
    set(THREADS_INCLUDE
      "/* lo/lo_serverthread.h unavailable (THREADING=OFF) */")
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_link_libraries(${LIBRARY_SHARED} "user32" "wsock32" "ws2_32" "iphlpapi")
    target_link_libraries(${LIBRARY_SHARED} "pthreadVC2")

    set_target_properties(${LIBRARY_SHARED} PROPERTIES
        COMPILE_DEFINITIONS "-DLIBLO_DLL")
    set_target_properties(${LIBRARY_STATIC} PROPERTIES
        COMPILE_DEFINITIONS "-DLIBLO_LIB")

    set(DLLNAME "")
    if(THREADING)
        set(DEFTHREADS "")
    else()
        set(DEFTHREADS ";;")
    endif()
else()
    target_link_libraries(${LIBRARY_SHARED} "m")
endif()

set(LO_INCLUDE_DIRS
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_include_directories(${LIBRARY_SHARED} PUBLIC ${LO_INCLUDE_DIRS})
target_include_directories(${LIBRARY_STATIC} PUBLIC ${LO_INCLUDE_DIRS})
target_include_directories(${OSCDUMP} PUBLIC ${LO_INCLUDE_DIRS})
target_include_directories(${OSCSEND} PUBLIC ${LO_INCLUDE_DIRS})

target_link_libraries(${OSCDUMP} PUBLIC ${LIBRARY_SHARED})
target_link_libraries(${OSCSEND} PUBLIC ${LIBRARY_SHARED})

# parse version info from configure.ac
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../configure.ac"
    CONFIGURE_AC_LINE REGEX "AC_INIT\\(\\[liblo\\].*\\)")
string(REGEX MATCHALL "[0-9]+" CONFIGURE_AC_LIST ${CONFIGURE_AC_LINE})
list(GET CONFIGURE_AC_LIST 0 CONFIGURE_AC_MAJOR)
list(GET CONFIGURE_AC_LIST 1 CONFIGURE_AC_MINOR)
set(PACKAGE_VERSION "${CONFIGURE_AC_MAJOR}.${CONFIGURE_AC_MINOR}")

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../configure.ac"
    CONFIGURE_AC_LINE REGEX "m4_define\\(\\[lt_current\\], [0-9]+\\)")
string(REGEX MATCHALL "[0-9]+" CONFIGURE_AC_LIST ${CONFIGURE_AC_LINE})
list(GET CONFIGURE_AC_LIST 1 CONFIGURE_AC_CURRENT)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../configure.ac"
    CONFIGURE_AC_LINE REGEX "m4_define\\(\\[lt_revision\\], [0-9]+\\)")
string(REGEX MATCHALL "[0-9]+" CONFIGURE_AC_LIST ${CONFIGURE_AC_LINE})
list(GET CONFIGURE_AC_LIST 1 CONFIGURE_AC_REVISION)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../configure.ac"
    CONFIGURE_AC_LINE REGEX "m4_define\\(\\[lt_age\\], [0-9]+\\)")
string(REGEX MATCHALL "[0-9]+" CONFIGURE_AC_LIST ${CONFIGURE_AC_LINE})
list(GET CONFIGURE_AC_LIST 1 CONFIGURE_AC_AGE)
set(LO_SO_VERSION
    "{${CONFIGURE_AC_CURRENT}, ${CONFIGURE_AC_REVISION}, ${CONFIGURE_AC_AGE}}")

math(EXPR CURRENT_MINUS_AGE "${CONFIGURE_AC_CURRENT} - ${CONFIGURE_AC_AGE}")
set_target_properties(${LIBRARY_SHARED} PROPERTIES
    VERSION   "${CURRENT_MINUS_AGE}.${CONFIGURE_AC_AGE}.${CONFIGURE_AC_REVISION}"
    SOVERSION "${CURRENT_MINUS_AGE}"
    OUTPUT_NAME "lo"
    )
set_target_properties(${LIBRARY_STATIC} PROPERTIES
    OUTPUT_NAME "lo"
    )

if(NOT DEFINED PRINTF_LL)
    message(STATUS "Check how to print long long int")
    try_compile(PRINTF_LL_AVAILABLE ${CMAKE_CURRENT_BINARY_DIR}
        SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/test-printf-ll.c")
    if(PRINTF_LL_AVAILABLE)
        set(PRINTF_LL "ll" CACHE INTERNAL "")
    else()
        try_compile(PRINTF_LL_AVAILABLE ${CMAKE_CURRENT_BINARY_DIR}
            SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/test-printf-I64.c")
        if(PRINTF_LL_AVAILABLE)
            set(PRINTF_LL "I64" CACHE INTERNAL "")
        else()
            message(FATAL_ERROR "printf doesn't support long long int")
        endif()
    endif()
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(VERSION "${CONFIGURE_AC_CURRENT}.${CONFIGURE_AC_REVISION}")
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/config-msvc.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/config.h)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/liblo.def.in
        ${CMAKE_CURRENT_BINARY_DIR}/src/liblo.def)
else()
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/config.h)
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../lo/lo.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/lo/lo.h)
test_big_endian(LO_BIGENDIAN)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../lo/lo_endian.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/lo/lo_endian.h)
configure_file(
    ${PROJECT}Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT}Config.cmake)

set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix "\${prefix}")
set(libdir "\${exec_prefix}/lib")
set(includedir "\${prefix}/include")
set(LIBPTHREAD ${CMAKE_THREAD_LIBS_INIT})
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../${PROJECT}.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT}.pc
    @ONLY)
add_definitions(-DHAVE_CONFIG_H)

install(
    TARGETS ${LIBRARY_STATIC} ${LIBRARY_SHARED} ${OSCDUMP} ${OSCSEND}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin)
install(
    FILES ${LIBRARY_HEADERS}
    DESTINATION include/lo)
install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT}Config.cmake
    DESTINATION lib/cmake/${PROJECT})
install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT}.pc
    DESTINATION lib/pkgconfig)
