cmake_minimum_required (VERSION 3.12)

project ("LiteCrypt")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/build/${CMAKE_BUILD_TYPE}/bin)

add_executable (${PROJECT_NAME} WIN32 "src/main.cpp" "logo.rc")

find_package(Qt5 COMPONENTS Core Widgets REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE 
    Qt5::Core 
    Qt5::Widgets
)
