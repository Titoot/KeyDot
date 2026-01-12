# KeyDot

**Blazingly Fast, Static Godot Engine Encryption Key Extractor**

[![Build Status](https://img.shields.io/github/actions/workflow/status/Titoot/KeyDot/build-and-release.yml?branch=main)](https://github.com/Titoot/KeyDot/actions/workflows/build-and-release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Latest Release](https://img.shields.io/github/v/release/Titoot/KeyDot)](https://github.com/Titoot/KeyDot/releases)

KeyDot is a high-performance, command-line utility designed to extract encryption keys and detect the engine version from compiled Godot Engine games. It operates directly on game executables (Windows x64) and WebAssembly (`.wasm`) files without ever needing to run the game.

## Key Features

-   **⚡ Blazing Fast Extraction:** Optimized C++ code and memory-mapped I/O provide results in milliseconds.
-   **🔬 Static Analysis:** Reads the game files directly. No runtime process attachment, memory dumping, or debugging required, making it safe and efficient.
-   **🧠 Memory-Efficient:** Uses memory-mapped files to let the operating system handle efficient file paging, keeping memory usage low even for huge executables.
-   **🌐 WASM Support:** The only static analysis tool currently available that can extract keys from Godot games compiled for the web.

## Performance Comparison

KeyDot was built from the ground up for speed and ease of use. Here's how it compares to other available tools:

| Tool                         | Standalone?¹ | Analysis Type | Speed (Windows)²              | Speed (WASM)³                 | Notes                                                    |
| ---------------------------- | :----------: | :-----------: | ----------------------------- | ----------------------------- | -------------------------------------------------------- |
| **KeyDot (This Project)**    |     ✅      |    Static     | **~50 ms**                    | **~6 ms**                     | Fully automated, no manual steps required.               |
| [gdke](https://github.com/char-ptr/gdke) |     ❌      |    Static     | Slow (large files)            | ❌ Not Supported             | Requires manual function signature search in IDA/Ghidra. |
| [GodotPCKExplorer](https://github.com/DmitriySalnikov/GodotPCKExplorer/tree/master/Bruteforcer) |     ✅      |    Static     | ~4000 ms                      | ❌ Not Supported             | Slower pattern scanning.                                 |
| [godot-key-extract](https://github.com/char-ptr/godot-key-extract) |      ❌      |    Dynamic    | Varies (fast)                 | ❌ Not Supported             | Requires DLL injection and running the game process.     |

¹ **Standalone** means the tool does not require running the game or using other complex software like debuggers or disassemblers.
² **Windows speed** tested on a 78MB executable for KeyDot and a 56MB executable for GodotPCKExplorer.
³ **WASM speed** tested on a 38MB `.wasm` file.

## Supported Platforms

-   ✅ **Windows** (64-bit PE Executables)
-   ✅ **WebAssembly** (`.wasm` files)
-   *Linux (ELF) and macOS (Mach-O) support is planned.*

## Installation

### 1. Pre-compiled Releases (Recommended)

The easiest way to use KeyDot is to download the latest pre-compiled executable for your platform from the [**Releases Page**](https://github.com/Titoot/KeyDot/releases).

### 2. Building from Source

If you prefer to build the project yourself, you will need a C++20 compatible compiler and CMake.

**Prerequisites:**
-   CMake 3.14+
-   A C++20 Compiler (Visual Studio 2022, GCC 11+, Clang 12+)

**Steps:**
1.  Clone the repository:
    ```sh
    git clone https://github.com/Titoot/KeyDot.git
    cd KeyDot
    ```
2.  Create a build directory:
    ```sh
    mkdir build
    cd build
    ```
3.  Configure and generate build files:
    ```sh
    cmake ..
    ```
4.  Compile the project:
    ```sh
    cmake --build . --config Release
    ```
The final executable, `keydot.exe`, will be in the `build/Release` directory.

## Usage

KeyDot is a simple command-line tool.

```
KeyDot - Blazingly Fast, Static Godot Engine Encryption Key Extractor
Note: Only 64-bit (x64) executables are supported at the moment.

Usage:
  KeyDot [options] <path-to-exe-or-wasm>

Options:
  -d, --debug       Enable detailed debug logging
  -t, --timers      Show execution time for each stage
  -h, --help        Show this help message and exit
```

### Examples

**1. Analyze a Windows Executable:**
```sh
keydot.exe game.exe
```
*Expected Output:*
```
Godot Engine version: 4.1.1.stable
Anchor          : Can't open encrypted pack directory.
String VA       : 0x140D2A5B0
LEA at          : 0x1406A1E1F
off_* qword VA  : 0x140D838B0
Blob VA         : 0x1411232B0
32-byte (hex)   : 1A2B3C4D5E6F78901A2B3C4D5E6F78901A2B3C4D5E6F78901A2B3C4D
```

**2. Analyze a WebAssembly File with Debug Output:**
```sh
keydot.exe --debug --timers game.wasm
```
*Expected Output:*
```
[CFG] Debug logging enabled
[CFG] Timer logging enabled
[IO] Detected WASM file
[TIMER] find_godot_version_in_wasm: 3.45 ms
Godot Engine version: 3.5.2.stable
[TIMER] extract_wasm_key: 2.11 ms
WASM key: 0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba
[TIMER] Total execution: 6.02 ms
```

## Reporting Issues

If you encounter a game where KeyDot fails to extract the key, or if you want to request support for a new platform (like Linux or macOS), please **open an issue**.

Make sure to include:
1.  The sample game file (or a link to it).
2.  The **full text output** of running KeyDot with the `--debug` flag.

## Extraction Approach

### Windows (PE Files)

1.  **Find Anchor String:** The process begins by searching for known error strings related to encrypted PCK loading (e.g., `"Can't open encrypted pack directory."`) within the (`.rdata`).
2.  **Locate Code Reference:** Once a string is located, the tool scans the (`.text`) to find where this string is referenced by an instruction, typically `LEA`.
3.  **Identify Key Pointer:** Within a small window of instructions following the `LEA`, the scanner looks for a crucial pattern: a `MOV` instruction that loads a 64-bit pointer from a global address (`MOV RAX, [RIP + offset]`).
4.  **Dereference Pointer:** This global address contains a *pointer to* the actual 32-byte encryption key blob, which typically resides in the `.data` section.
5.  **Extract Key:** The tool reads the 32-byte blob from this final address, revealing the key.

### WebAssembly (.wasm)

1.  **Heuristic Search:** Godot's export template for WASM often embeds the encryption key as a raw byte array near the end of the file.
2.  **Marker Identification:** KeyDot reads the last few kilobytes of the file and searches for a specific 7-byte "start marker" followed by a 4-byte "end marker".
3.  **Key Extraction:** The 32-byte encryption key is consistently located immediately preceding this end marker.

## Special Thanks

This project was made possible by studying the excellent work of the following projects and individuals:

-   [GDRETools/gdsdecomp](https://github.com/GDRETools/gdsdecomp)
-   [char-ptr/godot-key-extract](https://github.com/char-ptr/godot-key-extract) (Dynamic Analysis)
-   [char-ptr/gdke](https://github.com/char-ptr/gdke) (Static Analysis)
-   [DmitriySalnikov/GodotPCKExplorer/Bruteforcer](https://github.com/DmitriySalnikov/GodotPCKExplorer/tree/master/Bruteforcer)
-   The [Godot Engine](https://github.com/godotengine/godot) source code itself.
-   And finally, a huge thank you to my girlfriend for her endless support and encouragement throughout this project.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

### Disclaimer

This tool is intended for educational purposes, security research, and to assist in data recovery for your own projects. Please use it responsibly and respect the intellectual property rights of game developers. The author is not responsible for any misuse of this software.
