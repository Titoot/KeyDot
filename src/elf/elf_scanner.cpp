#include "keydot/elf_scanner.h"
#include "common/mapped_file.h"
#include "common/timer.h"
#include "common/utils.h"
#include "elf/elf_image.h"
#include "elf/elf_patterns.h"

#include <iostream>
#include <iomanip>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <functional>

namespace {

std::vector<size_t> find_subsequence(
    std::span<const uint8_t> haystack,
    size_t start,
    size_t length,
    std::string_view needle)
{
    Timer timer("find_subsequence '" + std::string(needle) + "'", false);
    if (start + length > haystack.size()) {
        length = haystack.size() - start;
    }

    std::vector<size_t> found_indices;
    auto search_area = haystack.subspan(start, length);
    std::span<const uint8_t> needle_span(
        reinterpret_cast<const uint8_t*>(needle.data()),
        needle.size()
    );

    auto it = search_area.begin();
    while (true) {
        it = std::search(it, search_area.end(), needle_span.begin(), needle_span.end());
        if (it == search_area.end()) {
            break;
        }
        // Calculate offset relative to the full haystack, not the subspan
        size_t absolute_offset = (it - haystack.begin());
        found_indices.push_back(absolute_offset);
        ++it; // Continue search after the found occurrence
    }

    timer.print_manual(std::string(needle), needle.length());
    return found_indices;
}

// Extract a bounded C-string view from [start, end).
// Returns a view from start to the first '\0' or end if no '\0' found.
inline std::string_view bounded_cstr_view(const char* start, const char* end) {
    const char* nul = std::find(start, end, '\0');
    return std::string_view(start, static_cast<size_t>(nul - start));
}

// Parse version substring "v<digits...>" from a string_view.
// Returns only the version part (without the 'v'), up to whitespace/end.
inline std::optional<std::string> parse_version_from_view(std::string_view s) {
    size_t pos = s.find('v');
    while (pos != std::string_view::npos) {
        if (pos + 1 < s.size() && std::isdigit(static_cast<unsigned char>(s[pos + 1]))) {
            size_t end = s.find_first_of(" \t", pos);
            const size_t start = pos + 1;
            const size_t count = (end == std::string_view::npos ? s.size() : end) - start;
            return std::string(s.substr(start, count));
        }
        pos = s.find('v', pos + 1);
    }
    return std::nullopt;
}

std::optional<std::string> find_godot_version_in_elf(const ELFImage& elf) {
    Timer timer("find_godot_version_in_elf");

    const Section* rodata = elf.get_section(".rodata");
    if (!rodata) {
        DBG("[GodotVer] .rodata section not found");
        return std::nullopt;
    }

    const uint8_t* base = elf.get_raw_data().data();
    const char* seg_begin = reinterpret_cast<const char*>(base + rodata->file_offset);
    const char* seg_end   = seg_begin + rodata->file_size;

    static const std::string needle = "Godot Engine";
    auto searcher = std::boyer_moore_searcher(needle.begin(), needle.end());

    DBG("[GodotVer] Scanning .rodata for '", needle, "' (", rodata->file_size, " bytes)");

    const char* pos = seg_begin;
    size_t occ_idx = 0;
    while (true) {
        auto it = std::search(pos, seg_end, searcher);
        if (it == seg_end) break; // no more matches
        ++occ_idx;

        std::string_view full_sv = bounded_cstr_view(it, seg_end);
        DBG("[GodotVer] Occurrence ", occ_idx, ": ", std::string(full_sv));

        if (auto ver = parse_version_from_view(full_sv)) {
            DBG("[GodotVer] Parsed version: ", *ver);
            return ver;
        }

        pos = it + needle.size();
    }

    DBG("[GodotVer] No occurrence contained a version pattern");
    return std::nullopt;
}

}

int scan_elf_file(const std::string& path) {
    // --- Stage 1: Memory Map the file ---
    MappedFile mapped_file(path);
    if (!mapped_file.is_valid()) {
        return 1; // MappedFile constructor already printed the error
    }

    // --- Stage 2: ELF parse ---
    Timer elf_parse_timer("ELFImage::parse");
    auto elf = ELFImage::parse(mapped_file.get_data());
    elf_parse_timer.~Timer();

    if (!elf || !elf->is_elf64()) {
        std::cerr << "Error: Not a valid ELF64 (x64) image." << std::endl;
        return 2;
    }

    DBG("[ELF] BaseAddress=0x", std::hex, elf->get_base_address(), std::dec);
    DBG("[ELF] Type=", (elf->get_elf_type() == ELFType::EXEC ? "ET_EXEC" : "ET_DYN"));
    DBG("[ELF] Section count: ", elf->get_sections().size());

    // --- Stage 3: section lookups ---
    const Section *text, *rodata, *data;
    {
        Timer section_lookup_timer("Section lookups");
        text = elf->get_section(".text");
        rodata = elf->get_section(".rodata");
        if (!rodata) {
            rodata = elf->get_section(".data.rel.ro");
        }
        data = elf->get_section(".data");
    }
    if (!text || !rodata || !data) {
        std::cerr << "Error: Required sections .text/.rodata/.data not found." << std::endl;
        return 3;
    }

    DBG("[SECT] .text VA=0x", std::hex, text->virtual_address, " size=0x", text->virtual_size, std::dec);
    DBG("[SECT] rodata (", rodata->name, ") VA=0x", std::hex, rodata->virtual_address, " size=0x", rodata->virtual_size, std::dec);
    DBG("[SECT] .data VA=0x", std::hex, data->virtual_address, " size=0x", data->virtual_size, std::dec);

    // Optional: Godot version extraction
    auto godot_ver = find_godot_version_in_elf(*elf);
    if (godot_ver) {
        std::cout << "Godot Engine version: " << *godot_ver << std::endl;
    } else {
        std::cout << "Could not determine Godot Engine version from ELF." << std::endl;
    }

    // --- Stage 4: anchor search loop ---
    const std::vector<std::string> anchors = {
        "Can't open encrypted pack directory.",
        "Can't open encrypted pack-referenced file '%s'.",
        "Condition \"fae.is_null()\" is true."
    };

    bool found = false;
    for (const auto& anchor_str : anchors) {
        Timer anchor_timer("Anchor '" + anchor_str + "' search");
        DBG("[ANCHOR] Searching for: '", anchor_str, "'");

        // 4a: Find the anchor string in the .rodata section
        auto hits = find_subsequence(elf->get_raw_data(), rodata->file_offset, rodata->file_size, anchor_str);
        DBG("[ANCHOR] Hits: ", hits.size());

        for (const auto& hit : hits) {
            uint32_t anchor_rva = rodata->virtual_address + static_cast<uint32_t>(hit - rodata->file_offset);
            uint64_t anchor_va = elf->get_base_address() + anchor_rva;
            DBG("[ANCHOR] VA=0x", std::hex, anchor_va, std::dec);

            // 4b: Find a `LEA` instruction in the .text section that points to our string
            uint64_t lea_site = find_lea_to_target_va(*elf, *text, anchor_va);
            if (lea_site == 0) {
                DBG("[LEA] Not found for anchor VA=0x", std::hex, anchor_va, std::dec);
                continue;
            }
            DBG("[LEA] Site=0x", std::hex, lea_site, std::dec);

            // 4c: Scan forward from AFTER the anchor instruction for the key blob load
            // GCC on Linux may place the key load far from the error string (up to 64KB away)
            auto load_instr_opt = find_rip_relative_load_in_window(*elf, *text, lea_site + 1, 0x600);
            if (!load_instr_opt) {
                DBG("[LOAD_SCAN] Not found in 0x600 window. Expanding to 0x10000...");
                load_instr_opt = find_rip_relative_load_in_window(*elf, *text, lea_site + 1, 0x10000);
                if (!load_instr_opt) {
                    DBG("[LOAD_SCAN] Not found in 0x10000 window either.");
                    continue;
                }
            }
            const auto& load_instr = *load_instr_opt;

            // 4d: Get the blob pointer VA, handling MOV vs LEA difference
            uint64_t ptr_to_blob_va = 0;
            if (load_instr.type == LoadType::MOV_DEREF) {
                // For MOV, the target_va is a pointer we must read to get the final address
                DBG("[SCAN] Instruction is MOV, reading pointer from 0x", std::hex, load_instr.target_va, std::dec);
                auto ptr_opt = elf->read_u64_va(load_instr.target_va);
                if (!ptr_opt) {
                    DBG("[READ] Failed to read pointer for MOV at VA=0x", std::hex, load_instr.target_va, std::dec);
                    continue;
                }
                ptr_to_blob_va = *ptr_opt;
            } else { // LoadType::LEA_ADDRESS
                DBG("[SCAN] Instruction is LEA, target VA is the pointer.");
                ptr_to_blob_va = load_instr.target_va;
            }
            DBG("[READ] Final Blob pointer VA=0x", std::hex, ptr_to_blob_va, std::dec);

            // 4e: Validate that the blob pointer is in a valid data section
            const Section* blob_data_section = nullptr;
            for (const auto& s : elf->get_sections()) {
                if ((s.name == ".data" || s.name == ".bss" || s.name == ".data.rel.ro") && is_va_in_section(ptr_to_blob_va, *elf, s)) {
                    blob_data_section = &s;
                    break;
                }
            }
            if (!blob_data_section) {
                DBG("[SECT] Final blob VA 0x", std::hex, ptr_to_blob_va, " not in any data section.", std::dec);
                continue;
            }
            DBG("[SECT] Blob VA is in section '", blob_data_section->name, "'.");

            // 4f: Read the final 32-byte key blob
            auto blob = elf->read_va(ptr_to_blob_va, 32);
            if (!blob || blob->size() != 32) {
                DBG("[READ] Blob read failed or not 32 bytes.");
                continue;
            }

            std::cout << std::left << std::setw(17) << "Anchor" << ": " << anchor_str << std::endl;
            std::cout << std::hex << std::uppercase << std::setfill('0');
            std::cout << std::left << std::setw(17) << "String VA" << ": 0x" << anchor_va << std::endl;
            std::cout << std::left << std::setw(17) << "LEA at" << ": 0x" << lea_site << std::endl;
            std::cout << std::left << std::setw(17) << "off_* qword VA" << ": 0x" << load_instr.target_va << std::endl;
            std::cout << std::left << std::setw(17) << "Blob VA" << ": 0x" << ptr_to_blob_va << std::endl;
            std::cout << std::dec << std::setfill(' ');
            std::cout << std::left << std::setw(17) << "32-byte (hex)" << ": " << hex_string(*blob) << std::endl;

            found = true;
            break;
        }

        if (found) break;
    }

    if (!found) {
        std::cerr << "Failed to locate the 32-byte key blob using the provided anchors." << std::endl;
        return 4;
    }

    return 0;
}
