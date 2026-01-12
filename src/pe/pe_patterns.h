#pragma once

#include "pe_image.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

/**
 * @brief Searches for a subsequence (needle) within a byte span (haystack).
 */
std::vector<size_t> find_subsequence(
    std::span<const uint8_t> haystack,
    size_t start,
    size_t length,
    std::string_view needle);

/**
 * @brief Checks if a virtual address is within a specific PE section.
 */
bool is_va_in_section(uint64_t va, const PEImage& pe, const Section& section);

/**
 * @brief Finds a LEA instruction that points to a target VA.
 */
uint64_t find_lea_to_target_va(const PEImage& pe, const Section& text_sec, uint64_t target_va);

/**
 * @brief Type of RIP-relative load instruction.
 */
enum class LoadType {
    MOV_DEREF,    ///< MOV instruction that dereferences a pointer
    LEA_ADDRESS   ///< LEA instruction that loads an address directly
};

/**
 * @brief Represents a RIP-relative load instruction and its target.
 */
struct RipRelativeLoad {
    uint64_t instruction_va; ///< Virtual address of the instruction
    uint64_t target_va;      ///< Virtual address that the instruction references
    LoadType type;           ///< Type of load instruction
};

/**
 * @brief Searches for RIP-relative load instructions around an anchor VA.
 */
std::optional<RipRelativeLoad> find_rip_relative_load_around_va(
    const PEImage& pe, const Section& text_sec, uint64_t anchor_va, size_t radius);

/**
 * @brief Finds a key load instruction near a 'mov edx, 20h' pattern.
 */
std::optional<RipRelativeLoad> find_key_load_near_mov_edx_20h(
    const PEImage& pe, const Section& text_sec, uint64_t lea_site, size_t search_radius);

/**
 * @brief Scans a specific range for RIP-relative load instructions.
 */
std::optional<RipRelativeLoad> find_rip_relative_in_range(
    const PEImage& pe, const Section& text_sec,
    size_t start_offset, size_t end_offset,
    uint64_t reference_va, bool require_data_section);