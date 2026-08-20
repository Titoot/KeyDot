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

    // First, try LEA with RIP-relative addressing (7 bytes: REX.W + 8D + ModR/M + disp32)
    // This is what MSVC typically generates on Windows.
    for (size_t i = 1; i < text_data.size() - 6; ++i) {
        if (text_data[i] == 0x8D) { // LEA opcode
            uint8_t rex = text_data[i - 1];
            if ((rex & 0xF8) == 0x48) { // REX.W prefix
                uint8_t modrm = text_data[i + 1];
                if (valid_modrm.count(modrm)) {
                    int32_t disp;
                    std::memcpy(&disp, &text_data[i + 2], sizeof(disp));

                    uint64_t instr_va = text_va_base + (i - 1);
                    uint64_t rip_after = instr_va + 7;
                    uint64_t calculated_target = rip_after + disp;

                    if (calculated_target == target_va) {
                        DBG("[find_lea] Found LEA at VA=0x", std::hex, instr_va);
                        return instr_va;
                    }
                }
            }
        }
    }

    // Second, try MOV r32, imm32 with 32-bit immediate (GCC on Linux often uses this).
    // For non-PIE binaries where addresses fit in 32 bits, GCC uses:
    //   MOV EAX-EDI, imm32: B8-BF + imm32 (5 bytes)
    //   MOV R8D-R15D, imm32: 41 B8-BF + imm32 (6 bytes, REX.B prefix)
    // The 32-bit value is zero-extended to 64 bits.
    if (target_va <= 0xFFFFFFFF) {
        uint32_t target_imm = static_cast<uint32_t>(target_va);

        for (size_t i = 0; i < text_data.size() - 5; ++i) {
            uint8_t byte = text_data[i];

            // Check for MOV EAX-EDI, imm32 (B8-BF)
            if (byte >= 0xB8 && byte <= 0xBF) {
                uint32_t imm;
                std::memcpy(&imm, &text_data[i + 1], sizeof(imm));
                if (imm == target_imm) {
                    uint64_t instr_va = text_va_base + i;
                    DBG("[find_lea] Found MOV r32,imm32 at VA=0x", std::hex, instr_va);
                    return instr_va;
                }
            }

            // Check for MOV R8D-R15D, imm32 (41 B8-BF)
            if (byte == 0x41 && i + 6 <= text_data.size()) {
                uint8_t opcode = text_data[i + 1];
                if (opcode >= 0xB8 && opcode <= 0xBF) {
                    uint32_t imm;
                    std::memcpy(&imm, &text_data[i + 2], sizeof(imm));
                    if (imm == target_imm) {
                        uint64_t instr_va = text_va_base + i;
                        DBG("[find_lea] Found MOV r32,imm32 (REX.B) at VA=0x", std::hex, instr_va);
                        return instr_va;
                    }
                }
            }
        }
    }

    DBG("[find_lea] No matching instruction found.");
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

    const uint64_t text_va_base = text_sec.virtual_address;

    // Helper lambda to check if an address is in a data section
    // Note: We prioritize .data over .bss because encryption keys are in initialized data.
    // .bss is uninitialized and often doesn't exist in the file.
    auto is_in_data_section = [&](uint64_t va) -> bool {
        for (const auto& s : elf.get_sections()) {
            if (s.name == ".data" || s.name == ".data.rel.ro") {
                if (is_va_in_section(va, elf, s)) {
                    return true;
                }
            }
        }
        return false;
    };

    for (size_t i = search_start; i + 6 < search_end; ++i) {
        // Pattern 1: REX.W + MOV/LEA with RIP-relative addressing (7 bytes)
        if ((text_data[i] & 0xF8) == 0x48) {
            uint8_t opcode = text_data[i + 1];

            if (opcode == 0x8B || opcode == 0x8D) { // MOV or LEA
                uint8_t modrm = text_data[i + 2];
                if ((modrm & 0xC7) == 0x05) { // RIP-relative addressing
                    int32_t disp;
                    std::memcpy(&disp, &text_data[i + 3], sizeof(disp));

                    uint64_t instr_va = text_va_base + i;
                    uint64_t rip_after = instr_va + 7;
                    uint64_t target_va = rip_after + disp;

                    uint64_t final_blob_va = 0;

                    if (opcode == 0x8B) { // MOV - dereference pointer
                        auto ptr_opt = elf.read_u64_va(target_va);
                        if (!ptr_opt) continue;
                        final_blob_va = *ptr_opt;
                    } else { // LEA - direct address
                        final_blob_va = target_va;
                    }

                    if (is_in_data_section(final_blob_va)) {
                        LoadType type = (opcode == 0x8B) ? LoadType::MOV_DEREF : LoadType::LEA_ADDRESS;
                        DBG("[LOAD_SCAN] Found valid ", (type == LoadType::MOV_DEREF ? "MOV" : "LEA"),
                            " at VA=0x", std::hex, instr_va, " -> VA=0x", final_blob_va, std::dec);
                        return RipRelativeLoad{instr_va, target_va, type};
                    }
                }
            }
        }

        // Pattern 2: MOV r32, imm32 (5 bytes) - GCC on Linux uses this for addresses < 2GB
        // Format: B8-BF + imm32 (loads into EAX-EDI)
        if (text_data[i] >= 0xB8 && text_data[i] <= 0xBF && i + 5 <= search_end) {
            uint32_t imm;
            std::memcpy(&imm, &text_data[i + 1], sizeof(imm));

            if (is_in_data_section(imm)) {
                uint64_t instr_va = text_va_base + i;
                DBG("[LOAD_SCAN] Found MOV r32,imm32 at VA=0x", std::hex, instr_va,
                    " loading addr=0x", imm, std::dec);
                return RipRelativeLoad{instr_va, imm, LoadType::LEA_ADDRESS};
            }
        }

        // Pattern 3: REX.B + MOV r32, imm32 (6 bytes)
        // Format: 41 B8-BF + imm32 (loads into R8D-R15D)
        if (text_data[i] == 0x41 && i + 6 <= search_end) {
            uint8_t opcode = text_data[i + 1];
            if (opcode >= 0xB8 && opcode <= 0xBF) {
                uint32_t imm;
                std::memcpy(&imm, &text_data[i + 2], sizeof(imm));

                if (is_in_data_section(imm)) {
                    uint64_t instr_va = text_va_base + i;
                    DBG("[LOAD_SCAN] Found MOV r32,imm32 (REX.B) at VA=0x", std::hex, instr_va,
                        " loading addr=0x", imm, std::dec);
                    return RipRelativeLoad{instr_va, imm, LoadType::LEA_ADDRESS};
                }
            }
        }
    }

    DBG("[LOAD_SCAN] No valid MOV/LEA found in window.");
    return std::nullopt;
}
