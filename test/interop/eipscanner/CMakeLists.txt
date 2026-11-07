cmake_minimum_required(VERSION 3.10)
project(eip_peer CXX)

set(CMAKE_CXX_STANDARD 20)
set(EIPSCANNER "/usr/local" CACHE PATH "Where EIPScanner is installed")

add_executable(eip_peer main.cpp)
target_include_directories(eip_peer PRIVATE ${EIPSCANNER}/include/EIPScanner)
target_link_directories(eip_peer PRIVATE ${EIPSCANNER}/lib)
target_link_libraries(eip_peer EIPScannerS)
