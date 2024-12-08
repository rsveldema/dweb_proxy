set(BOOST_USE_STATIC_LIBS        ON)  # only find static libs
set(BOOST_INCLUDE_LIBRARIES thread filesystem system program_options asio coroutine beast url)
set(BOOST_ENABLE_CMAKE ON)

include(FetchContent)
FetchContent_Declare(
  Boost
  GIT_REPOSITORY https://github.com/boostorg/boost.git
  GIT_TAG boost-1.86.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(Boost)


set(LIB "dweb_proxy_lib")
set(PROG "dweb_proxy")

add_library(${LIB} 
  AutoDiscovery.cpp  
  server.cpp 
  request_handler.cpp)
set_property(TARGET ${LIB} PROPERTY CXX_STANDARD 20)
target_include_directories(${LIB} PUBLIC include) 

target_compile_definitions(${LIB}
  PUBLIC 
  BOOST_ASIO_SEPARATE_COMPILATION=1
)

target_link_libraries(${LIB} PUBLIC
  Boost::filesystem
  Boost::beast
  Boost::thread  
  Boost::system 
  Boost::asio
  Boost::coroutine
  Boost::program_options
  Boost::url
    ssl
    crypto
    spdlog
    fmt
    avahi-core
    avahi-common
    avahi-client
)


add_executable(${PROG} main.cpp)

target_link_libraries(${PROG} PRIVATE
    ${LIB}
)