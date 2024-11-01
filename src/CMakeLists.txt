
find_package(Boost REQUIRED)
find_package(Threads REQUIRED)


set(LIB "dweb_proxy_lib")
set(PROG "dweb_proxy")

add_library(${LIB} server.cc)
target_include_directories(${LIB} PUBLIC include)
target_link_libraries(${LIB} PRIVATE
    Boost::headers
    Threads::Threads
    ssl
    crypto
)

add_executable(${PROG} main.cc)

target_link_libraries(${PROG} PRIVATE
    ${LIB}
)