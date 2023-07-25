
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was Config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

####################################################################################


set(VOLE_PSI_ENABLE_SSE ON)
set(VOLE_PSI_PIC ON)
set(VOLE_PSI_STD_VER 17)
set(VOLE_PSI_ENABLE_GMW ON)
set(VOLE_PSI_ENABLE_CPSI ON)
set(VOLE_PSI_ENABLE_OPPRF ON)
set(VOLE_PSI_ENABLE_BOOST ON)
set(VOLE_PSI_ENABLE_OPENSSL ON)
set(VOLE_PSI_ENABLE_BITPOLYMUL ON)
set(VOLE_PSI_ENABLE_SODIUM ON)
set(VOLE_PSI_SODIUM_MONTGOMERY ON)
set(VOLE_PSI_ENABLE_RELIC ON)

include("${CMAKE_CURRENT_LIST_DIR}/volePSITargets.cmake")

include("${CMAKE_CURRENT_LIST_DIR}/findDependancies.cmake")


get_target_property(volePSI_INCLUDE_DIRS visa::volePSI INTERFACE_INCLUDE_DIRECTORIES)

get_target_property(volePSI_LIBRARIES visa::volePSI LOCATION)

message("volePSI_INCLUDE_DIRS=${volePSI_INCLUDE_DIRS}")
message("volePSI_LIBRARIES=${volePSI_LIBRARIES}")
