#include "elf_image.h"
#include "common/timer.h"
#include "common/utils.h"

#include <cstring>
#include <algorithm>
#include <iostream>

namespace {
    // Helper functions to read little-endian values from a buffer safely.
    template<typename T>
    T read_from_buffer(std::span<const uint8_t> buffer, size_t offset) {
        T value;
        std::memcpy(&value, buffer.data() + offset, sizeof(T));
        return value;
    }

    uint16_t read_u16(std::span<const uint8_t> b, size_t off) { return read_from_buffer<uint16_t>(b, off); }
    uint32_t read_u32(std::span<const uint8_t> b, size_t off) { return read_from_buffer<uint32_t>(b, off); }
    uint64_t read_u64(std::span<const uint8_t> b, size_t off) { return read_from_buffer<uint64_t>(b, off); }

    // ELF constants
    constexpr uint16_t ET_EXEC = 2;
    constexpr uint16_t ET_DYN = 3;
}

ELFImage::ELFImage(std::span<const uint8_t> data) : m_data(data) {}

std::unique_ptr<ELFImage> ELFImage::parse(std::span<const uint8_t> data) {
    Timer timer("ELF parse");

    // --- ELF Header Checks (64 bytes minimum) ---
    if (data.size() < 64) return nullptr;

    // Check ELF magic: 0x7F 'E' 'L' 'F'
    if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        return nullptr;
    }

    // Check for 64-bit class (EI_CLASS at offset 0x04)
    if (data[4] != 2) { // ELFCLASS64
        DBG("[ELF] Not a 64-bit ELF file. Class: ", static_cast<int>(data[4]));
        return nullptr;
    }

    // Check for little-endian (EI_DATA at offset 0x05)
    if (data[5] != 1) { // ELFDATA2LSB
        DBG("[ELF] Not a little-endian ELF file. Data encoding: ", static_cast<int>(data[5]));
        return nullptr;
    }

    // Read ELF type (ET_EXEC or ET_DYN) at offset 0x10
    uint16_t e_type = read_u16(data, 0x10);

    // Read section header table offset (e_shoff) at offset 0x28
    uint64_t e_shoff = read_u64(data, 0x28);

    // Read section header entry size (e_shentsize) at offset 0x3A
    uint16_t e_shentsize = read_u16(data, 0x3A);

    // Read number of section headers (e_shnum) at offset 0x3C
    uint16_t e_shnum = read_u16(data, 0x3C);

    // Read section header string table index (e_shstrndx) at offset 0x3E
    uint16_t e_shstrndx = read_u16(data, 0x3E);

    DBG("[ELF] e_type=", e_type, " e_shoff=", e_shoff, " e_shnum=", e_shnum, " e_shstrndx=", e_shstrndx);

    // Validate section header table
    if (e_shoff + static_cast<uint64_t>(e_shnum) * e_shentsize > data.size()) {
        DBG("[ELF] Section header table extends beyond file size.");
        return nullptr;
    }

    // --- Create and Populate Image ---
    auto img = std::unique_ptr<ELFImage>(new ELFImage(data));
    img->m_is_elf64 = true;

    // Set ELF type
    // Note: ELF section sh_addr values are already absolute VAs, so base_address
    // should be 0. Unlike PE where sections have RVAs relative to ImageBase,
    // ELF section headers contain the actual virtual addresses.
    if (e_type == ET_EXEC) {
        img->m_elf_type = ELFType::EXEC;
        img->m_base_address = 0; // Section addresses are already absolute VAs
    } else if (e_type == ET_DYN) {
        img->m_elf_type = ELFType::DYN;
        img->m_base_address = 0; // PIE - use section addresses directly
    } else {
        DBG("[ELF] Unknown e_type: ", e_type);
        return nullptr;
    }

    // Read the section header string table section header
    if (e_shstrndx >= e_shnum) {
        DBG("[ELF] Invalid e_shstrndx: ", e_shstrndx);
        return nullptr;
    }

    uint64_t shstrtab_shdr_offset = e_shoff + static_cast<uint64_t>(e_shstrndx) * e_shentsize;
    if (shstrtab_shdr_offset + 64 > data.size()) {
        DBG("[ELF] String table section header out of bounds.");
        return nullptr;
    }

    // Read string table section offset and size
    img->m_shstrtab_offset = read_u64(data, shstrtab_shdr_offset + 0x18); // sh_offset
    img->m_shstrtab_size = read_u64(data, shstrtab_shdr_offset + 0x20);   // sh_size

    if (img->m_shstrtab_offset + img->m_shstrtab_size > data.size()) {
        DBG("[ELF] String table extends beyond file size.");
        return nullptr;
    }

    DBG("[ELF] String table at offset ", img->m_shstrtab_offset, " size ", img->m_shstrtab_size);

    // --- Parse Section Headers ---
    for (uint16_t i = 0; i < e_shnum; ++i) {
        uint64_t shdr_offset = e_shoff + static_cast<uint64_t>(i) * e_shentsize;
        if (shdr_offset + 64 > data.size()) break;

        uint32_t sh_name = read_u32(data, shdr_offset + 0x00);      // Name offset in string table
        uint64_t sh_addr = read_u64(data, shdr_offset + 0x10);      // Virtual address
        uint64_t sh_offset = read_u64(data, shdr_offset + 0x18);    // File offset
        uint64_t sh_size = read_u64(data, shdr_offset + 0x20);      // Section size

        std::string section_name = img->read_section_name(sh_name);

        // Skip empty sections
        if (section_name.empty() || sh_size == 0) continue;

        img->m_sections.emplace_back(Section{
            section_name,
            static_cast<uint32_t>(sh_addr),
            static_cast<uint32_t>(sh_size),
            static_cast<uint32_t>(sh_offset),
            static_cast<uint32_t>(sh_size)
        });

        DBG("[ELF] Section: ", section_name, " addr=0x", std::hex, sh_addr, " offset=0x", sh_offset, " size=0x", sh_size, std::dec);
    }

    return img;
}

std::string ELFImage::read_section_name(uint32_t name_offset) const {
    if (name_offset >= m_shstrtab_size) {
        return "";
    }

    // Find null terminator
    uint64_t start = m_shstrtab_offset + name_offset;
    uint64_t end = m_shstrtab_offset + m_shstrtab_size;

    const uint8_t* name_start = m_data.data() + start;
    const uint8_t* name_end = m_data.data() + end;
    const uint8_t* null_pos = static_cast<const uint8_t*>(std::memchr(name_start, '\0', name_end - name_start));

    if (null_pos) {
        return std::string(reinterpret_cast<const char*>(name_start), null_pos - name_start);
    }

    return "";
}

const Section* ELFImage::get_section(const std::string& name) const {
    auto it = std::find_if(m_sections.begin(), m_sections.end(), [&](const Section& s) {
        return s.name == name;
    });
    return (it != m_sections.end()) ? &(*it) : nullptr;
}

int64_t ELFImage::va_to_file_offset(uint64_t va) const {
    // For PIE (ET_DYN), va is already relative to base 0
    // For non-PIE (ET_EXEC), subtract the base address
    uint64_t adjusted_va = va;
    if (m_elf_type == ELFType::EXEC && va >= m_base_address) {
        adjusted_va = va - m_base_address;
    }

    for (const auto& s : m_sections) {
        if (adjusted_va >= s.virtual_address && adjusted_va < s.virtual_address + s.virtual_size) {
            uint32_t delta = adjusted_va - s.virtual_address;
            int64_t offset = static_cast<int64_t>(s.file_offset) + delta;

            // Sanity check
            if (offset >= 0 && static_cast<size_t>(offset) < m_data.size()) {
                return offset;
            }
        }
    }
    return -1;
}

std::optional<std::vector<uint8_t>> ELFImage::read_va(uint64_t va, size_t size) const {
    int64_t offset = va_to_file_offset(va);
    if (offset < 0 || static_cast<size_t>(offset) + size > m_data.size()) {
        DBG("[READ] read_va(0x", std::hex, va, ", ", std::dec, size, ") failed: out of bounds.");
        return std::nullopt;
    }

    auto start_it = m_data.begin() + offset;
    auto end_it = start_it + size;
    return std::vector<uint8_t>(start_it, end_it);
}

std::optional<uint64_t> ELFImage::read_u64_va(uint64_t va) const {
    auto buf_opt = read_va(va, 8);
    if (!buf_opt) {
        return std::nullopt;
    }
    return read_u64(*buf_opt, 0);
}
