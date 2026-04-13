#include "mapped_file.h"

#ifdef _WIN32

#include "utils.h" // For DBG
#include <iostream>

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

#else // !_WIN32

#include "utils.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

MappedFile::MappedFile(const std::string& path) {
    m_fd = ::open(path.c_str(), O_RDONLY);
    if (m_fd < 0) {
        std::cerr << "Error: Could not open file " << path << ": " << std::strerror(errno) << std::endl;
        return;
    }

    struct stat st {};
    if (::fstat(m_fd, &st) != 0) {
        std::cerr << "Error: Could not stat file: " << std::strerror(errno) << std::endl;
        ::close(m_fd);
        m_fd = -1;
        return;
    }

    if (!S_ISREG(st.st_mode)) {
        std::cerr << "Error: Not a regular file." << std::endl;
        ::close(m_fd);
        m_fd = -1;
        return;
    }

    m_file_size = static_cast<size_t>(st.st_size);
    DBG("[IO] File size: ", m_file_size, " bytes");

    if (m_file_size == 0) {
        m_pMappedData = nullptr;
        DBG("[IO] Empty file; no mmap");
        return;
    }

    m_pMappedData = ::mmap(nullptr, m_file_size, PROT_READ, MAP_PRIVATE, m_fd, 0);
    if (m_pMappedData == MAP_FAILED) {
        std::cerr << "Error: Could not mmap file: " << std::strerror(errno) << std::endl;
        m_pMappedData = nullptr;
        ::close(m_fd);
        m_fd = -1;
        return;
    }

    DBG("[IO] Mapped view @ ", m_pMappedData, " size=", m_file_size, " bytes");
}

MappedFile::~MappedFile() {
    if (m_pMappedData && m_pMappedData != MAP_FAILED && m_file_size > 0) {
        ::munmap(m_pMappedData, m_file_size);
    }
    if (m_fd >= 0) {
        ::close(m_fd);
    }
}

bool MappedFile::is_valid() const {
    if (m_fd < 0) {
        return false;
    }
    if (m_file_size == 0) {
        return true;
    }
    return m_pMappedData != nullptr && m_pMappedData != MAP_FAILED;
}

std::span<const uint8_t> MappedFile::get_data() const {
    if (!is_valid() || m_file_size == 0) {
        return {};
    }
    return { static_cast<const uint8_t*>(m_pMappedData), m_file_size };
}

#endif // _WIN32
