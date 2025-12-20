#include "mapped_file.h"
#include "utils.h" // For DBG
#include <iostream>

#ifdef _WIN32
// Windows implementation
MappedFile::MappedFile(const std::string& path) {
    m_hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Could not open file " << path << std::endl;
        return;
    }

    LARGE_INTEGER file_size_li;
    if (!GetFileSizeEx(m_hFile, &file_size_li)) {
        std::cerr << "Error: Could not get file size." << std::endl;
        return;
    }
    m_file_size = static_cast<size_t>(file_size_li.QuadPart);
    DBG("[IO] File size: ", m_file_size, " bytes");

    m_hMapping = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (m_hMapping == NULL) {
        std::cerr << "Error: Could not create file mapping." << std::endl;
        return;
    }

    m_pMappedData = MapViewOfFile(m_hMapping, FILE_MAP_READ, 0, 0, 0);
    if (m_pMappedData == NULL) {
        std::cerr << "Error: Could not map view of file." << std::endl;
        return;
    }

    DBG("[IO] Mapped view @ ", m_pMappedData, " size=", m_file_size, " bytes");
}

MappedFile::~MappedFile() {
    if (m_pMappedData) UnmapViewOfFile(m_pMappedData);
    if (m_hMapping) CloseHandle(m_hMapping);
    if (m_hFile != INVALID_HANDLE_VALUE) CloseHandle(m_hFile);
}

bool MappedFile::is_valid() const {
    return m_pMappedData != NULL;
}

std::span<const uint8_t> MappedFile::get_data() const {
    return { static_cast<const uint8_t*>(m_pMappedData), m_file_size };
}

#else
// Linux/POSIX implementation
MappedFile::MappedFile(const std::string& path) {
    m_fd = open(path.c_str(), O_RDONLY);
    if (m_fd == -1) {
        std::cerr << "Error: Could not open file " << path << std::endl;
        return;
    }

    struct stat sb;
    if (fstat(m_fd, &sb) == -1) {
        std::cerr << "Error: Could not get file size." << std::endl;
        return;
    }
    m_file_size = static_cast<size_t>(sb.st_size);
    DBG("[IO] File size: ", m_file_size, " bytes");

    m_pMappedData = mmap(nullptr, m_file_size, PROT_READ, MAP_PRIVATE, m_fd, 0);
    if (m_pMappedData == MAP_FAILED) {
        std::cerr << "Error: Could not map file into memory." << std::endl;
        m_pMappedData = nullptr;
        return;
    }

    DBG("[IO] Mapped view @ ", m_pMappedData, " size=", m_file_size, " bytes");
}

MappedFile::~MappedFile() {
    if (m_pMappedData != nullptr) {
        munmap(m_pMappedData, m_file_size);
    }
    if (m_fd != -1) {
        close(m_fd);
    }
}

bool MappedFile::is_valid() const {
    return m_pMappedData != nullptr;
}

std::span<const uint8_t> MappedFile::get_data() const {
    return { static_cast<const uint8_t*>(m_pMappedData), m_file_size };
}

#endif