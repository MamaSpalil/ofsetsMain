# ==========================================================
# MuTracker - MuOnline Process Tracker
# CMake Build System
#
# Builds:
#   - MuTrackerDLL.dll   (injectable DLL for in-process tracking)
#   - MuTrackerLoader.exe (external launcher and process manager)
#
# Requirements:
#   - CMake 3.15+
#   - MSVC 2022 or compatible (x86 target)
#   - Windows SDK
#
# Build:
#   mkdir build && cd build
#   cmake .. -G "Visual Studio 17 2022" -A Win32
#   cmake --build . --config Release
# ==========================================================

cmake_minimum_required(VERSION 3.15)
project(MuTracker VERSION 1.0.0 LANGUAGES C CXX)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Force 32-bit build (MuOnline main.exe is x86)
if(MSVC)
    if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
        message(WARNING "MuTracker targets x86 (32-bit). Use -A Win32 for MSVC.")
    endif()
endif()

# Compiler warnings
if(MSVC)
    add_compile_options(/W4 /WX- /MP /permissive-)
    add_compile_definitions(
        WIN32
        _WINDOWS
        _CRT_SECURE_NO_WARNINGS
        UNICODE
        _UNICODE
    )
    # Release optimizations
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL /Gy")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")
endif()

# ==========================================================
# Source file lists
# ==========================================================

# Disassembler sources
set(DISASM_SOURCES
    src/disasm/hde32.c
    src/disasm/DisasmEngine.cpp
)
set(DISASM_HEADERS
    src/disasm/hde32.h
    src/disasm/table32.h
    src/disasm/DisasmEngine.h
)

# Core module sources
set(CORE_SOURCES
    src/core/MemoryUtils.cpp
    src/core/PatternScanner.cpp
    src/core/HookEngine.cpp
    src/core/CallTracer.cpp
)
set(CORE_HEADERS
    src/core/MemoryUtils.h
    src/core/PatternScanner.h
    src/core/HookEngine.h
    src/core/CallTracer.h
)

# Attach module sources
set(ATTACH_SOURCES
    src/attach/ProcessAttacher.cpp
    src/attach/DLLInjector.cpp
)
set(ATTACH_HEADERS
    src/attach/ProcessAttacher.h
    src/attach/DLLInjector.h
)

# Logger sources
set(LOG_SOURCES
    src/log/Logger.cpp
)
set(LOG_HEADERS
    src/log/Logger.h
)

# Config sources
set(CONFIG_SOURCES
    src/config/Config.cpp
)
set(CONFIG_HEADERS
    src/config/Config.h
)

# All library sources
set(LIB_SOURCES
    ${DISASM_SOURCES}
    ${CORE_SOURCES}
    ${LOG_SOURCES}
    ${CONFIG_SOURCES}
)
set(LIB_HEADERS
    ${DISASM_HEADERS}
    ${CORE_HEADERS}
    ${LOG_HEADERS}
    ${CONFIG_HEADERS}
)

# ==========================================================
# Static library (shared between DLL and Loader)
# ==========================================================

add_library(MuTrackerLib STATIC
    ${LIB_SOURCES}
    ${LIB_HEADERS}
)

target_include_directories(MuTrackerLib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(WIN32)
    target_link_libraries(MuTrackerLib PUBLIC
        psapi
    )
endif()

# ==========================================================
# MuTrackerDLL - Injectable DLL
# ==========================================================

add_library(MuTrackerDLL SHARED
    dll/MuTrackerDLL/dllmain.cpp
)

target_link_libraries(MuTrackerDLL PRIVATE
    MuTrackerLib
)

target_include_directories(MuTrackerDLL PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Set DLL output name
set_target_properties(MuTrackerDLL PROPERTIES
    OUTPUT_NAME "MuTrackerDLL"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ==========================================================
# MuTrackerLoader - External Launcher
# ==========================================================

add_executable(MuTrackerLoader
    loader/MuTrackerLoader/main.cpp
    ${ATTACH_SOURCES}
    ${ATTACH_HEADERS}
)

target_link_libraries(MuTrackerLoader PRIVATE
    MuTrackerLib
)

target_include_directories(MuTrackerLoader PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set_target_properties(MuTrackerLoader PROPERTIES
    OUTPUT_NAME "MuTrackerLoader"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Console subsystem for Loader
if(MSVC)
    set_target_properties(MuTrackerLoader PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )
endif()

# ==========================================================
# Copy config file to output directory
# ==========================================================

add_custom_command(TARGET MuTrackerLoader POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/config.json"
        "${CMAKE_BINARY_DIR}/bin/config.json"
    COMMENT "Copying config.json to output directory"
)

# ==========================================================
# Install targets
# ==========================================================

install(TARGETS MuTrackerDLL MuTrackerLoader
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION bin
)

install(FILES config.json DESTINATION bin)

# ==========================================================
# Source groups for IDE project organization
# ==========================================================

source_group("Core"     FILES ${CORE_SOURCES} ${CORE_HEADERS})
source_group("Disasm"   FILES ${DISASM_SOURCES} ${DISASM_HEADERS})
source_group("Attach"   FILES ${ATTACH_SOURCES} ${ATTACH_HEADERS})
source_group("Log"      FILES ${LOG_SOURCES} ${LOG_HEADERS})
source_group("Config"   FILES ${CONFIG_SOURCES} ${CONFIG_HEADERS})
