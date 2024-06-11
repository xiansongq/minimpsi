cmake_minimum_required(VERSION 3.15)
project(minimpsi)

include_directories(cPSI)
include_directories(miniMPSI)
include_directories(frontend)
include_directories(MPSI)
include_directories(dhoprf)
include_directories(cpsi)
include_directories(minimpsi)



file(GLOB_RECURSE SRCS
    cPSI/*.cpp
    miniMPSI/*.cpp
    frontend/*.cpp
    dhoprf/*.cpp
    cpsi/*.cpp
    minimpsi/*.cpp
)

add_executable(miniMPSI ${SRCS})

find_package(volePSI REQUIRED HINTS "./libvolepsi")

set(CMAKE_BUILD_TYPE Release)

target_compile_options(miniMPSI PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -lpthread -O3)
target_link_libraries(miniMPSI visa::volePSI)

# # for test
# add_executable(testBeaver test/Beaver_test.cpp common/util.cpp circuit/Circuit.cpp)
# target_compile_options(testBeaver PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -lpthread -O3)
# target_link_libraries(testBeaver visa::volePSI)

# add_executable(test_oprf test/test_oprf.cpp)
# target_compile_options(test_oprf PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -lpthread -O3)
# target_link_libraries(test_oprf visa::volePSI)


# add_executable(mycpsi test/test_minicpsi.cpp cpsi/cpsi.cpp dhoprf/Dhoprf.cpp)
# target_compile_options(mycpsi PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -lpthread -O3)
# target_link_libraries(mycpsi visa::volePSI )

# add_executable(minimpsi test/test_minimpsi.cpp minimpsi/minimpsi.cpp dhoprf/Dhoprf.cpp)
# target_compile_options(minimpsi PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++17> -lpthread -O3)
# target_link_libraries(minimpsi visa::volePSI )