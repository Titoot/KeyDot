#include "pe_patterns.h"
#include "common/timer.h"
#include "common/utils.h"

#include <algorithm>
#include <array>
#include <functional>
#include <unordered_set>
#include <iostream>
#include <cstring>

// Common patterns and constants
constexpr uint8_t REX_W_PREFIX = 0x48;
constexpr uint8_t LEA_OPCODE = 0x8D;
constexpr uint8_t MOV_OPCODE = 0x8B;
constexpr uint8_t MOVZX_OPCODE_1 = 0x0F;
constexpr uint8_t MOVZX_OPCODE_2 = 0xB6;

// Valid ModR/M bytes for [RIP + disp32] addressing (00_REG_101)
static const std::array<uint8_t, 8> VALID_MODRM_BYTES = {
    0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D
};

static bool is_va_in_named_section(uint64_t va, const PEImage& pe, 
                                  const std::vector<std::string>& section_prefixes) {
    for (const auto& section : pe.get_sections()) {
        for (const auto& prefix : section_prefixes) {
            if (section.name.rfind(prefix, 0) == 0) {
                if (is_va_in_section(va, pe, section)) {
                    return true;
                }
                break;
            }
        }
    }
    return false;
}

static std::optional<RipRelativeLoad> match_rip_relative_instruction(
    const uint8_t* data, size_t data_size, size_t offset,
    uint64_t base_va, const PEImage& pe,
    const std::vector<std::string>& allowed_sections) {
    
    if (offset + 6 >= data_size) {
        return std::nullopt;
    }

    const uint8_t rex = data[offset];
    if ((rex & 0xF0) != 0x40) {
        return std::nullopt;
    }
    if ((rex & 0x08) == 0) {
        return std::nullopt;
    }

    const uint8_t opcode = data[offset + 1];
    if (opcode != MOV_OPCODE && opcode != LEA_OPCODE) {
        return std::nullopt;
    }

    const uint8_t modrm = data[offset + 2];
    bool valid_modrm = false;
    for (auto valid : VALID_MODRM_BYTES) {
        if (modrm == valid) {
            valid_modrm = true;
            break;
        }
    }
    if (!valid_modrm) {
        return std::nullopt;
    }

    int32_t disp;
    std::memcpy(&disp, &data[offset + 3], sizeof(disp));

    const uint64_t instr_va = base_va + offset;
    const uint64_t rip_after = instr_va + 7;
    const uint64_t target_va = rip_after + disp;

    uint64_t final_va = target_va;
    if (opcode == MOV_OPCODE) {
        auto ptr = pe.read_u64_va(target_va);
        if (!ptr) {
            return std::nullopt;
        }
        final_va = *ptr;
    }

    if (!allowed_sections.empty() && 
        !is_va_in_named_section(final_va, pe, allowed_sections)) {
        return std::nullopt;
    }

    return RipRelativeLoad{
        instr_va,
        target_va,
        opcode == MOV_OPCODE ? LoadType::MOV_DEREF : LoadType::LEA_ADDRESS
    };
}

static std::vector<size_t> find_pattern_in_span(
    const uint8_t* haystack, size_t haystack_size,
    const uint8_t* needle, size_t needle_size) {
    
    std::vector<size_t> indices;
    
    for (size_t i = 0; i + needle_size <= haystack_size; ++i) {
        bool found = true;
        for (size_t j = 0; j < needle_size; ++j) {
            if (haystack[i + j] != needle[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            indices.push_back(i);
        }
    }
    
    return indices;
}

std::vector<size_t> find_subsequence(
    std::span<const uint8_t> haystack,
    size_t start,
    size_t length,
    std::string_view needle) {
    
    Timer timer("find_subsequence", false);
    
    if (start >= haystack.size()) {
        return {};
    }
    
    length = std::min(length, haystack.size() - start);
    
    const uint8_t* haystack_ptr = haystack.data() + start;
    const uint8_t* needle_ptr = reinterpret_cast<const uint8_t*>(needle.data());
    size_t needle_size = needle.size();
    
    auto indices = find_pattern_in_span(haystack_ptr, length, needle_ptr, needle_size);
    
    for (auto& idx : indices) {
        idx += start;
    }
    
    timer.print_manual(std::string(needle), needle.length());
    return indices;
}

bool is_va_in_section(uint64_t va, const PEImage& pe, const Section& section) {
    const uint64_t start_va = pe.get_image_base() + section.virtual_address;
    const uint64_t end_va = start_va + section.virtual_size;
    const bool in_section = (va >= start_va && va < end_va);
    
    if (is_debug_enabled()) {
        DBG("[is_va_in_section] VA=0x", std::hex, va, " section=", section.name,
            " range=[0x", start_va, ", 0x", end_va, ") -> ", 
            std::boolalpha, in_section, std::dec);
    }
    
    return in_section;
}

uint64_t find_lea_to_target_va(const PEImage& pe, const Section& text_sec, uint64_t target_va) {
    Timer timer("find_lea_to_target_va");
    DBG("[find_lea] target_va=0x", std::hex, target_va, std::dec);
    
    auto text_data = pe.get_raw_data().subspan(text_sec.file_offset, text_sec.file_size);
    if (text_data.size() < 7) return 0;
    
    const uint64_t text_va_base = pe.get_image_base() + text_sec.virtual_address;
    const uint8_t* data = text_data.data();
    size_t data_size = text_data.size();
    
    // Search for REX.W (0x48) + LEA (0x8D) pattern
    for (size_t i = 1; i < data_size - 6; ++i) {
        if (data[i] == LEA_OPCODE) {
            const uint8_t rex = data[i - 1];
            if ((rex & 0xF0) != 0x40 || (rex & 0x08) == 0) {
                continue;
            }
            const uint8_t modrm = data[i + 1];
            bool valid_modrm = false;
            for (auto valid : VALID_MODRM_BYTES) {
                if (modrm == valid) {
                    valid_modrm = true;
                    break;
                }
            }
            
            if (valid_modrm) {
                int32_t disp;
                std::memcpy(&disp, &data[i + 2], sizeof(disp));
                
                const uint64_t instr_va = text_va_base + (i - 1);
                const uint64_t rip_after = instr_va + 7;
                const uint64_t calculated_target = rip_after + disp;
                
                if (calculated_target == target_va) {
                    DBG("[find_lea] Found LEA at VA=0x", std::hex, instr_va);
                    return instr_va;
                }
            }
        }
    }
    
    DBG("[find_lea] No matching LEA instruction found.");
    return 0;
}

std::optional<RipRelativeLoad> find_key_load_near_mov_edx_20h(
    const PEImage& pe, const Section& text_sec, uint64_t lea_site, size_t search_radius) {
    
    Timer timer("find_key_load_near_mov_edx_20h");
    DBG("[EDX_SEARCH] Starting search near LEA at 0x", std::hex, lea_site, 
        " radius=0x", search_radius, std::dec);
    
    auto text_data = pe.get_raw_data().subspan(text_sec.file_offset, text_sec.file_size);
    const uint64_t text_va_base = pe.get_image_base() + text_sec.virtual_address;
    const uint8_t* data = text_data.data();
    size_t data_size = text_data.size();
    
    const int64_t lea_offset = pe.va_to_file_offset(lea_site);
    if (lea_offset < 0) {
        DBG("[EDX_SEARCH] Invalid LEA VA");
        return std::nullopt;
    }
    
    const size_t lea_in_text = lea_offset - text_sec.file_offset;
    const size_t search_start = (lea_in_text > search_radius) ? lea_in_text - search_radius : 0;
    const size_t search_end = std::min(lea_in_text + search_radius, data_size);
    
    DBG("[EDX_SEARCH] Searching in text range [0x", std::hex, 
        text_va_base + search_start, "-0x", text_va_base + search_end, ")", std::dec);
    
    // Look for "mov edx, 20h" pattern (BA 20 00 00 00)
    for (size_t i = search_start; i + 4 < search_end; ++i) {
        if (data[i] == 0xBA && 
            data[i + 1] == 0x20 &&
            data[i + 2] == 0x00 &&
            data[i + 3] == 0x00 &&
            data[i + 4] == 0x00) {
            
            const uint64_t edx_instr_va = text_va_base + i;
            DBG("[EDX_SEARCH] Found 'mov edx, 20h' at VA=0x", std::hex, edx_instr_va, std::dec);
            
            const size_t key_search_start = i + 5;
            const size_t key_search_end = std::min(key_search_start + 0x200, data_size);
            
            for (size_t j = key_search_start; j + 6 < key_search_end; ++j) {
                auto match = match_rip_relative_instruction(data, data_size, j,
                                                           text_va_base, pe,
                                                           {".data"});
                if (match) {
                    return RipRelativeLoad{match->instruction_va, match->target_va, match->type};
                }
            }
            break;
        }
    }
    
    DBG("[EDX_SEARCH] No 'mov edx, 20h' pattern found in search radius");
    return std::nullopt;
}

std::optional<RipRelativeLoad> find_rip_relative_in_range(
    const PEImage& pe, const Section& text_sec, 
    size_t start_offset, size_t end_offset,
    uint64_t reference_va, bool require_data_section) {
    
    auto text_data = pe.get_raw_data().subspan(text_sec.file_offset, text_sec.file_size);
    const uint64_t text_va_base = pe.get_image_base() + text_sec.virtual_address;
    const uint8_t* data = text_data.data();
    size_t data_size = text_data.size();
    
    const std::vector<std::string> allowed_sections = require_data_section ?
        std::vector<std::string>{".data"} :
        std::vector<std::string>{".data", ".rdata"};
    
    for (size_t i = start_offset; i + 6 < end_offset && i + 6 < data_size; ++i) {
        auto match = match_rip_relative_instruction(data, data_size, i,
                                                   text_va_base, pe,
                                                   allowed_sections);
        if (match) {
            return RipRelativeLoad{match->instruction_va, match->target_va, match->type};
        }
    }
    
    return std::nullopt;
}

std::optional<RipRelativeLoad> find_rip_relative_load_around_va(
    const PEImage& pe, const Section& text_sec, uint64_t anchor_va, size_t radius) {
    
    Timer timer("find_rip_relative_load_around_va");
    DBG("[AROUND_SCAN] anchor_va=0x", std::hex, anchor_va, " radius=", std::dec, radius);
    
    const int64_t anchor_offset = pe.va_to_file_offset(anchor_va);
    if (anchor_offset < 0) {
        DBG("[AROUND_SCAN] anchor_va is not a valid address.");
        return std::nullopt;
    }
    
    auto text_data = pe.get_raw_data().subspan(text_sec.file_offset, text_sec.file_size);
    const uint64_t text_va_base = pe.get_image_base() + text_sec.virtual_address;
    const uint8_t* data = text_data.data();
    size_t data_size = text_data.size();
    
    const size_t anchor_in_text = anchor_offset - text_sec.file_offset;
    const size_t search_start = (anchor_in_text > radius) ? anchor_in_text - radius : 0;
    const size_t search_end = std::min(anchor_in_text + radius, data_size);
    
    DBG("[AROUND_SCAN] Searching in range [0x", std::hex, 
        text_va_base + search_start, "-0x", text_va_base + search_end, 
        ") relative to anchor at 0x", anchor_va, std::dec);
    
    // Pattern 1: Key-loading loop pattern (LEA + MOVZX)
    for (size_t i = search_start; i + 11 < search_end; ++i) {
        // Check for LEA pattern: 48 8D 05 ?? ?? ?? ??
        if ((data[i] & 0xF0) == 0x40 && (data[i] & 0x08) != 0 && data[i + 1] == LEA_OPCODE) {
            uint8_t modrm = data[i + 2];
            bool valid_modrm = false;
            for (auto valid : VALID_MODRM_BYTES) {
                if (modrm == valid) {
                    valid_modrm = true;
                    break;
                }
            }
            
            if (valid_modrm) {
                // Check for MOVZX pattern: 41 0F B6 04 07
                if (data[i + 7] == 0x41 && data[i + 8] == MOVZX_OPCODE_1 &&
                    data[i + 9] == MOVZX_OPCODE_2 && data[i + 10] == 0x04 &&
                    data[i + 11] == 0x07) {
                    
                    int32_t disp;
                    std::memcpy(&disp, &data[i + 3], sizeof(disp));
                    
                    const uint64_t instr_va = text_va_base + i;
                    const uint64_t rip_after = instr_va + 7;
                    const uint64_t target_va = rip_after + disp;
                    
                    if (pe.read_va(target_va, 32)) {
                        DBG("[AROUND_SCAN] Found PATTERN 1 at VA=0x", std::hex, instr_va);
                        return RipRelativeLoad{instr_va, target_va, LoadType::LEA_ADDRESS};
                    }
                }
            }
        }
    }
    
    // Pattern 2: MOV EDX, 20h followed by RIP-relative instruction
    for (size_t i = search_start; i + 4 < search_end; ++i) {
        if (data[i] == 0xBA && 
            data[i + 1] == 0x20 &&
            data[i + 2] == 0x00 &&
            data[i + 3] == 0x00 &&
            data[i + 4] == 0x00) {
            
            const size_t pattern_start = i + 5;
            const size_t pattern_end = std::min(i + 0x100, search_end);
            
            for (size_t j = pattern_start; j + 6 < pattern_end; ++j) {
                auto match = match_rip_relative_instruction(data, data_size, j,
                                                           text_va_base, pe,
                                                           {});
                if (match) {
                    // Check if it points to valid 32-byte data
                    uint64_t final_va = match->type == LoadType::MOV_DEREF ?
                        *pe.read_u64_va(match->target_va) : match->target_va;
                    
                    if (pe.read_va(final_va, 32)) {
                        DBG("[AROUND_SCAN] Found PATTERN 2 at VA=0x", std::hex, match->instruction_va);
                        return RipRelativeLoad{match->instruction_va, match->target_va, match->type};
                    }
                }
            }
        }
    }
    
    // Pattern 3: General search with filtering
    std::optional<RipRelativeLoad> best_match;
    size_t best_distance = std::numeric_limits<size_t>::max();
    
    for (size_t i = search_start; i + 6 < search_end; ++i) {
        auto match = match_rip_relative_instruction(data, data_size, i,
                                                   text_va_base, pe,
                                                   {});
        if (match) {
            if (match->instruction_va == anchor_va) {
                continue;
            }
            
            const size_t distance = (i > anchor_in_text) ? (i - anchor_in_text) : (anchor_in_text - i);
            
            uint64_t final_va = match->type == LoadType::MOV_DEREF ?
                *pe.read_u64_va(match->target_va) : match->target_va;
            
            if (pe.read_va(final_va, 32) && distance < best_distance) {
                best_match = match;
                best_distance = distance;
            }
        }
    }
    
    if (best_match) {
        DBG("[AROUND_SCAN] Selected candidate at VA=0x", std::hex, best_match->instruction_va,
            " distance=0x", best_distance, std::dec);
        return RipRelativeLoad{best_match->instruction_va, best_match->target_va, best_match->type};
    }
    
    DBG("[AROUND_SCAN] No valid MOV/LEA found in radius.");
    return std::nullopt;
}