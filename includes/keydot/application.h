#pragma once
#include "common/config.h"

class Application {
public:
    int run(int argc, char* argv[]);

private:
    void print_usage() const;
    bool parse_arguments(int argc, char* argv[]);
    int process_file() const;
    bool is_wasm_file(const std::string& path) const;
    bool is_elf_file(const std::string& path) const;

    Config m_config;
};