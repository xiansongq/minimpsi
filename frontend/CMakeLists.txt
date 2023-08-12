
file(GLOB_RECURSE SRCS *.cpp )
file(GLOB MINIMPSI_SRCS "miniMPSI/*.cpp")
include_directories(${CMAKE_SOURCE_DIR}/frontend/)
add_executable(frontend  ${SRCS} )
# if you want to use the bloomFilter please link OpenMP to use threads
# FIND_PACKAGE(OpenMP REQUIRED)
# target_link_libraries(frontend volePSI OpenMP::OpenMP_CXX miniMPSI )

target_link_libraries(frontend volePSI  miniMPSI )


if(VOLE_PSI_NO_LTO)
    target_link_options(frontend PUBLIC "-fno-lto")
endif()



if(MSVC)
    target_compile_options(frontend PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${VOLE_PSI_STD_VER}>)
    #target_compile_options(libOTe PRIVATE -openmp:experimental)
else()
    target_compile_options(frontend PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${VOLE_PSI_STD_VER}>)
endif()