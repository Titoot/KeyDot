#include "keydot/pe_scanner.h"
#include "common/mapped_file.h"
#include "common/timer.h"
#include "common/utils.h"
#include "pe/pe_image.h"
#include "pe/pe_patterns.h"

#include <iostream>
#include <iomanip>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <functional> // For std::boyer_moore_searcher

namespace {
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

std::optional<std::string> find_godot_version_in_pe(const PEImage& pe) {
    Timer timer("find_godot_version_in_pe");

    const Section* rdata = pe.get_section(".rdata");
    if (!rdata) {
        DBG("[GodotVer] .rdata section not found");
        return std::nullopt;
    }

    const uint8_t* base = pe.get_raw_data().data();
    const char* seg_begin = reinterpret_cast<const char*>(base + rdata->file_offset);
    const char* seg_end   = seg_begin + rdata->file_size;

    static const std::string needle = "Godot Engine";
    auto searcher = std::boyer_moore_searcher(needle.begin(), needle.end());

    DBG("[GodotVer] Scanning .rdata for '", needle, "' (", rdata->file_size, " bytes)");

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

int scan_pe_file(const std::string& path) {
    // --- Stage 1: Memory Map the file ---
    MappedFile mapped_file(path);
    if (!mapped_file.is_valid()) {
        return 1; // MappedFile constructor already printed the error
    }

    // --- Stage 2: PE parse ---
    Timer pe_parse_timer("PEImage::parse");
    auto pe = PEImage::parse(mapped_file.get_data());
    pe_parse_timer.~Timer();

    if (!pe || !pe->is_pe64()) {
        std::cerr << "Error: Not a valid PE32+ (x64) image." << std::endl;
        return 2;
    }

    DBG("[PE] ImageBase=0x", std::hex, pe->get_image_base(), std::dec);
    DBG("[PE] Section count: ", pe->get_sections().size());

    // --- Stage 3: section lookups ---
    const Section *text, *rdata, *data;
    {
        Timer section_lookup_timer("Section lookups");
        text = pe->get_section(".text");
        rdata = pe->get_section(".rdata");
        data = pe->get_section(".data"); // Main .data section
    }
    if (!text || !rdata || !data) {
        std::cerr << "Error: Required sections .text/.rdata/.data not found." << std::endl;
        return 3;
    }

    DBG("[SECT] .text RVA=0x", std::hex, text->virtual_address, " size=0x", text->virtual_size, std::dec);
    DBG("[SECT] .rdata RVA=0x", std::hex, rdata->virtual_address, " size=0x", rdata->virtual_size, std::dec);
    DBG("[SECT] .data RVA=0x", std::hex, data->virtual_address, " size=0x", data->virtual_size, std::dec);

    // Optional: Godot version extraction
    auto godot_ver = find_godot_version_in_pe(*pe);
    if (godot_ver) {
        std::cout << "Godot Engine version: " << *godot_ver << std::endl;
    } else {
        std::cout << "Could not determine Godot Engine version from EXE." << std::endl;
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

        // 4a: Find the anchor string in the .rdata section
        auto hits = find_subsequence(pe->get_raw_data(), rdata->file_offset, rdata->file_size, anchor_str);
        DBG("[ANCHOR] Hits: ", hits.size());

        for (const auto& hit : hits) {
            uint32_t anchor_rva = rdata->virtual_address + static_cast<uint32_t>(hit - rdata->file_offset);
            uint64_t anchor_va = pe->get_image_base() + anchor_rva;
            DBG("[ANCHOR] RVA=0x", std::hex, anchor_rva, " VA=0x", anchor_va, std::dec);

            // 4b: Find a `LEA` instruction in the .text section that points to our string
            uint64_t lea_site = find_lea_to_target_va(*pe, *text, anchor_va);
            if (lea_site == 0) {
                DBG("[LEA] Not found for anchor VA=0x", std::hex, anchor_va, std::dec);
                continue;
            }
            DBG("[LEA] Site=0x", std::hex, lea_site, std::dec);

            // 4c: Scan forward from AFTER the LEA for the relevant MOV or LEA instruction
            auto load_instr_opt = find_rip_relative_load_in_window(*pe, *text, lea_site + 1, 0x600);
            if (!load_instr_opt) {
                DBG("[LOAD_SCAN] Not found in 0x600 window. Expanding to 0x1000...");
                load_instr_opt = find_rip_relative_load_in_window(*pe, *text, lea_site + 1, 0x1000);
                if (!load_instr_opt) {
                    DBG("[LOAD_SCAN] Not found in 0x1000 window either.");
                    continue;
                }
            }
            const auto& load_instr = *load_instr_opt;

            // 4d: Get the blob pointer VA, handling MOV vs LEA difference
            uint64_t ptr_to_blob_va = 0;
            if (load_instr.type == LoadType::MOV_DEREF) {
                // For MOV, the target_va is a pointer we must read to get the final address
                DBG("[SCAN] Instruction is MOV, reading pointer from 0x", std::hex, load_instr.target_va, std::dec);
                auto ptr_opt = pe->read_u64_va(load_instr.target_va);
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
            for (const auto& s : pe->get_sections()) {
                if (s.name.rfind(".data", 0) == 0 && is_va_in_section(ptr_to_blob_va, *pe, s)) {
                    blob_data_section = &s;
                    break;
                }
            }
            if (!blob_data_section) {
                DBG("[SECT] Final blob VA 0x", std::hex, ptr_to_blob_va, " not in any .data* section.", std::dec);
                continue;
            }
            DBG("[SECT] Blob VA is in section '", blob_data_section->name, "'.");

            // 4f: Read the final 32-byte key blob
            auto blob = pe->read_va(ptr_to_blob_va, 32);
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