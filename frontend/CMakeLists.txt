
file(GLOB_RECURSE SRCS *.cpp )
# 查找 miniMPSI 目录下的所有源文件
file(GLOB MINIMPSI_SRCS "miniMPSI/*.cpp")
include_directories(${CMAKE_SOURCE_DIR}/frontend/)
add_executable(frontend  ${SRCS} )
FIND_PACKAGE(OpenMP REQUIRED)
## OpenMP::OpenMP_CXX
target_link_libraries(frontend volePSI OpenMP::OpenMP_CXX miniMPSI )


if(VOLE_PSI_NO_LTO)
    target_link_options(frontend PUBLIC "-fno-lto")
endif()



if(MSVC)
    target_compile_options(frontend PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${VOLE_PSI_STD_VER}>)
    #target_compile_options(libOTe PRIVATE -openmp:experimental)
else()
    target_compile_options(frontend PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${VOLE_PSI_STD_VER}>)
endif()