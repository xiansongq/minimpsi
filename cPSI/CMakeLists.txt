# 添加所有源文件到库
file(GLOB_RECURSE MPSI_SRCS *.cpp)
add_library(cPSI ${MPSI_SRCS})

# 链接库
target_link_libraries(cPSI PRIVATE volePSI )