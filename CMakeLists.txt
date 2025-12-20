cmake_minimum_required(VERSION 3.14)
project(KeyDot CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Common Library (Utilities) ---
add_library(keydot_common
    src/common/utils.cpp
    src/common/timer.cpp
    src/common/mapped_file.cpp
    # Add wasm_utils here as it's a shared utility
    src/wasm/wasm_utils.cpp
)
target_include_directories(keydot_common
    PUBLIC
        # This allows includes like <config.h> directly from other common files
        ${CMAKE_CURRENT_SOURCE_DIR}/src/common
        # This allows wasm_scanner to find wasm_utils.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/wasm
)

# --- PE Library ---
add_library(keydot_pe
    src/pe/pe_image.cpp
    src/pe/pe_patterns.cpp
    src/pe/pe_scanner.cpp
)
target_include_directories(keydot_pe
    PUBLIC
        # Add the root include dir for "keydot/pe_scanner.h"
        ${CMAKE_CURRENT_SOURCE_DIR}/includes
    PRIVATE
        # Add src so we can find "common/..." and "pe/..." headers
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(keydot_pe PRIVATE keydot_common)

# --- WASM Library ---
add_library(keydot_wasm
    src/wasm/wasm_scanner.cpp
)
target_include_directories(keydot_wasm
    PUBLIC
        # Add the root include dir for "keydot/wasm_scanner.h"
        ${CMAKE_CURRENT_SOURCE_DIR}/includes
    PRIVATE
        # Add src so we can find "common/..." and "wasm/..." headers
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(keydot_wasm PRIVATE keydot_common)

# --- ELF Library ---
add_library(keydot_elf
    src/elf/elf_image.cpp
    src/elf/elf_patterns.cpp
    src/elf/elf_scanner.cpp
)
target_include_directories(keydot_elf
    PUBLIC
        # Add the root include dir for "keydot/elf_scanner.h"
        ${CMAKE_CURRENT_SOURCE_DIR}/includes
    PRIVATE
        # Add src so we can find "common/..." and "elf/..." headers
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(keydot_elf PRIVATE keydot_common)

# --- Main Executable ---
add_executable(keydot
    src/app/main.cpp
    src/app/application.cpp
)
target_include_directories(keydot
    PUBLIC
        # Add the root include dir for "keydot/application.h"
        ${CMAKE_CURRENT_SOURCE_DIR}/includes
    PRIVATE
        # Add src so we can find "common/..." headers
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(keydot
    PRIVATE
        keydot_common
        keydot_pe
        keydot_wasm
        keydot_elf
)

# --- Compiler Flags ---
if(MSVC)
    target_compile_options(keydot PRIVATE "$<$<CONFIG:Release>:/O2>")
else()
    target_compile_options(keydot PRIVATE "$<$<CONFIG:Release>:-O3>")
endif()