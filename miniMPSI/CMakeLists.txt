file(GLOB_RECURSE MPSI_SRCS *.cpp)
add_library(miniMPSI ${MPSI_SRCS})
# FIND_PACKAGE(OpenMP REQUIRED)
# OpenMP::OpenMP_CXX
target_link_libraries(miniMPSI PRIVATE volePSI )