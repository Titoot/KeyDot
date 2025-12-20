#include "keydot/application.h"
#include "keydot/pe_scanner.h"
#include "keydot/wasm_scanner.h"
#include "keydot/elf_scanner.h"
#include "common/utils.h"
#include "common/timer.h"
#include <iostream>
#include <fstream>

int Application::run(int argc, char* argv[]) {
    if (!parse_arguments(argc, argv)) {
        return 1;
    }

    // Apply configuration
    set_debug_enabled(m_config.debug);
    set_timer_enabled(m_config.timers);
    if (is_debug_enabled()) DBG("[CFG] Debug logging enabled");
    if (is_timer_enabled()) DBG("[CFG] Timer logging enabled");

    Timer total_timer("Total execution");
    return process_file();
}

void Application::print_usage() const {
    std::cerr
        << "KeyDot - Blazingly Fast, Static Godot Engine Encryption Key Extractor\n"
        << "Note: Only 64-bit (x64) executables are supported at the moment.\n\n"
        << "Usage:\n"
        << "  KeyDot [options] <path-to-exe-elf-or-wasm>\n\n"
        << "Options:\n"
        << "  -d, --debug       Enable detailed debug logging\n"
        << "  -t, --timers      Show execution time for each stage\n"
        << "  -h, --help        Show this help message and exit\n\n"
        << "Examples:\n"
        << "  KeyDot game.exe           Extract key/version from a Godot EXE\n"
        << "  KeyDot game.x86_64        Extract key/version from a Godot ELF file\n"
        << "  KeyDot -d game.wasm       Debug extraction from a Godot WASM file\n"
        << std::endl;
}

bool Application::parse_arguments(int argc, char* argv[]) {
  // Loop through all arguments, skipping the program name at index 0
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--debug" || arg == "-d") {
            m_config.debug = true;
        } else if (arg == "--timers" || arg == "-t") {
            m_config.timers = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return false; // Signal to exit gracefully
        } else if (arg.rfind("--", 0) == 0) {
            std::cerr << "Error: Unknown option '" << arg << "'" << std::endl;
            print_usage();
            return false; // Signal error
        } else if (m_config.file_path.empty()) {
            // This is the first non-option argument, treat it as the file path
            m_config.file_path = arg;
        } else {
            // We already have a file path, so this is an unexpected extra argument
            std::cerr << "Error: Unexpected extra argument '" << arg << "'" << std::endl;
            print_usage();
            return false; // Signal error
        }
    }

    // After parsing, check if a file path was provided.
    // This handles the case where the user provides options but no file.
    if (m_config.file_path.empty()) {
        std::cerr << "Error: No input file specified." << std::endl;
        print_usage();
        return false; // Signal error
    }

    // If we get here, all arguments were valid.
    return true;
}

bool Application::is_wasm_file(const std::string& path) const {
    if (path.size() >= 5 && path.substr(path.size() - 5) == ".wasm") return true;
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    char magic[4];
    f.read(magic, 4);
    return f.gcount() == 4 && magic[0] == '\0' && magic[1] == 'a' && magic[2] == 's' && magic[3] == 'm';
}

bool Application::is_elf_file(const std::string& path) const {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    char magic[4];
    f.read(magic, 4);
    return f.gcount() == 4 && magic[0] == '\x7F' && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

int Application::process_file() const {
    if (is_wasm_file(m_config.file_path)) {
        return scan_wasm_file(m_config.file_path);
    } else if (is_elf_file(m_config.file_path)) {
        DBG("[IO] Detected ELF file");
        return scan_elf_file(m_config.file_path);
    } else {
        // Assume PE file, let the scanner handle errors if it's not
        return scan_pe_file(m_config.file_path);
    }
}