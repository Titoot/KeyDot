#include "elf_patterns.h"
#include "common/timer.h"
#include "common/utils.h"

#include <algorithm>
#include <unordered_set>
#include <iostream>
#include <cstring>

bool is_va_in_section(uint64_t va, const ELFImage& elf, const Section& section) {
    uint64_t start_va = elf.get_base_address() + section.virtual_address;
    uint64_t end_va = start_va + section.virtual_size;
    bool in_section = (va >= start_va && va < end_va);

    // DBG call is useful but can be very noisy, so it's good to have it conditional
    if (is_debug_enabled()) {
        DBG("[is_va_in_section] VA=0x", std::hex, va, " section=", section.name,
            " range=[0x", start_va, ", 0x", end_va, ") -> ", std::boolalpha, in_section, std::dec);
    }
    return in_section;
}

uint64_t find_lea_to_target_va(const ELFImage& elf, const Section& text_sec, uint64_t target_va) {
    Timer timer("find_lea_to_target_va");
    DBG("[find_lea] target_va=0x", std::hex, target_va, std::dec);

    auto text_data = elf.get_raw_data().subspan(text_sec.file_offset, text_sec.file_size);
    if (text_data.size() < 7) return 0;

    const uint64_t text_va_base = elf.get_base_address() + text_sec.virtual_address;

    // A set of valid ModR/M bytes for [RIP + disp32] addressing with any register operand.
    // The format is 00_REG_101.
    static const std::unordered_set<uint8_t> valid_modrm = {
        0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D
    };

    // We are looking for REX.W + 8D + ModR/M + disp32.
    // Start search at index 1 to allow checking for REX prefix at i-1.
    for (size_t i = 1; i < text_data.size() - 6; ++i) {
        // Opcode for LEA is 0x8D
        if (text_data[i] == 0x8D) {
            uint8_t rex = text_data[i - 1];
            // REX.W prefix for 64-bit operand is 0x48
            if (rex == 0x48) {
                uint8_t modrm = text_data[i + 1];
                if (valid_modrm.count(modrm)) {
                    int32_t disp;
                    std::memcpy(&disp, &text_data[i + 2], sizeof(disp));

                    uint64_t instr_va = text_va_base + (i - 1);
                    uint64_t rip_after = instr_va + 7; // RIP is value after the instruction
                    uint64_t calculated_target = rip_after + disp;

                    if (calculated_target == target_va) {
                        DBG("[find_lea] Found LEA at VA=0x", std::hex, instr_va);
                        return instr_va;
                    }
                }
            }
        }
    }
    DBG("[find_lea] No matching LEA instruction found.");
    return 0;
}

std::optional<RipRelativeLoad> find_rip_relative_load_in_window(
    const ELFImage& elf, const Section& text_sec, uint64_t from_va, size_t window)
{
    Timer timer("find_rip_relative_load_in_window");
    DBG("[LOAD_SCAN] from_va=0x", std::hex, from_va, " window=", std::dec, window);

    int64_t start_offset = elf.va_to_file_offset(from_va);
    if (start_offset < 0) {
        DBG("[LOAD_SCAN] from_va is not a valid address.");
        return std::nullopt;
    }

    auto text_data = elf.get_raw_data().subspan(text_sec.file_offset, text_sec.file_size);
    size_t search_start = start_offset - text_sec.file_offset;
    size_t search_end = std::min(search_start + window, text_data.size());

    const uint64_t text_va_base = elf.get_base_address() + text_sec.virtual_address;

    for (size_t i = search_start; i + 6 < search_end; ++i) {
        if (text_data[i] == 0x48) { // REX.W prefix
            uint8_t opcode = text_data[i + 1];

            if (opcode == 0x8B || opcode == 0x8D) { // MOV or LEA
                uint8_t modrm = text_data[i + 2];
                if ((modrm & 0xC7) == 0x05) { // Check for RIP-relative addressing
                    int32_t disp;
                    std::memcpy(&disp, &text_data[i + 3], sizeof(disp));

                    uint64_t instr_va = text_va_base + i;
                    uint64_t rip_after = instr_va + 7;
                    uint64_t target_va = rip_after + disp;

                    uint64_t final_blob_va = 0;
                    bool is_valid = false;

                    if (opcode == 0x8B) { // MOV
                        auto ptr_opt = elf.read_u64_va(target_va);
                        if (!ptr_opt) {
                            continue;
                        }
                        final_blob_va = *ptr_opt;
                    } else { // LEA
                        final_blob_va = target_va;
                    }

                    // Check if the FINAL address (after any dereferencing) is in a .data section.
                    for (const auto& s : elf.get_sections()) {
                        if (s.name == ".data" || s.name == ".bss" || s.name == ".data.rel.ro") {
                            if (is_va_in_section(final_blob_va, elf, s)) {
                                is_valid = true;
                                break;
                            }
                        }
                    }

                    if (is_valid) {
                        LoadType type = (opcode == 0x8B) ? LoadType::MOV_DEREF : LoadType::LEA_ADDRESS;
                        DBG("[LOAD_SCAN] Found valid ", (type == LoadType::MOV_DEREF ? "MOV" : "LEA"), " at VA=0x", std::hex, instr_va,
                            " leading to final VA=0x", final_blob_va, " in a data section.", std::dec);
                        return RipRelativeLoad{instr_va, target_va, type};
                    }
                }
            }
        }
    }

    DBG("[LOAD_SCAN] No valid MOV/LEA found in window.");
    return std::nullopt;
}
