# 添加所有源文件到库
file(GLOB_RECURSE MPSI_SRCS *.cpp)
add_library(miniMPSI ${MPSI_SRCS})
# FIND_PACKAGE(OpenMP REQUIRED)
# OpenMP::OpenMP_CXX
# 链接库
target_link_libraries(miniMPSI PRIVATE volePSI )