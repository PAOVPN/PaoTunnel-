cmake_minimum_required(VERSION 3.22.1)

project("native-lib")

add_library(
    native-lib
    SHARED
    native-lib.cpp
)

set_target_properties(native-lib PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_VISIBILITY_PRESET hidden
    C_VISIBILITY_PRESET hidden
)

target_compile_options(native-lib PRIVATE
    -O2
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -fno-exceptions
    -fno-rtti
)

target_link_options(native-lib PRIVATE
    -Wl,--gc-sections
    -Wl,-s
    -Wl,-z,max-page-size=16384
)
