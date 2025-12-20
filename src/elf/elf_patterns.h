#pragma once

#include <vector>
#include <string_view>
#include <optional>
#include <span>
#include "elf_image.h"

bool is_va_in_section(uint64_t va, const ELFImage& elf, const Section& section);
uint64_t find_lea_to_target_va(const ELFImage& elf, const Section& text_sec, uint64_t target_va);

enum class LoadType {
    MOV_DEREF,
    LEA_ADDRESS
};

struct RipRelativeLoad {
    uint64_t instruction_va;
    uint64_t target_va;
    LoadType type;
};

std::optional<RipRelativeLoad> find_rip_relative_load_in_window(
    const ELFImage& elf, const Section& text_sec, uint64_t from_va, size_t window);
