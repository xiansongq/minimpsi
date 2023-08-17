file(GLOB_RECURSE MPSI_SRCS *.cpp)
add_library(cPSI ${MPSI_SRCS})

target_link_libraries(cPSI PRIVATE volePSI )