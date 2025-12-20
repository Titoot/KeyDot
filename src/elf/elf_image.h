#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <memory>
#include <optional>

struct Section {
    std::string name;
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t file_offset;
    uint32_t file_size;
};

enum class ELFType {
    EXEC,  // Non-PIE (ET_EXEC)
    DYN    // PIE (ET_DYN)
};

class ELFImage {
public:
    static std::unique_ptr<ELFImage> parse(std::span<const uint8_t> data);

    // Disable copy/move operations for simplicity
    ELFImage(const ELFImage&) = delete;
    ELFImage& operator=(const ELFImage&) = delete;

    bool is_elf64() const { return m_is_elf64; }
    uint64_t get_base_address() const { return m_base_address; }
    ELFType get_elf_type() const { return m_elf_type; }
    const std::vector<Section>& get_sections() const { return m_sections; }
    std::span<const uint8_t> get_raw_data() const { return m_data; }

    const Section* get_section(const std::string& name) const;
    int64_t va_to_file_offset(uint64_t va) const;
    std::optional<std::vector<uint8_t>> read_va(uint64_t va, size_t size) const;
    std::optional<uint64_t> read_u64_va(uint64_t va) const;

private:
    explicit ELFImage(std::span<const uint8_t> data);
    std::string read_section_name(uint32_t name_offset) const;

    std::span<const uint8_t> m_data;
    std::vector<Section> m_sections;
    uint64_t m_base_address = 0;
    uint64_t m_shstrtab_offset = 0;  // Section header string table offset
    uint64_t m_shstrtab_size = 0;    // Section header string table size
    ELFType m_elf_type = ELFType::DYN;
    bool m_is_elf64 = false;
};
