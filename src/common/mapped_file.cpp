#include "mapped_file.h"
#include "utils.h" // For DBG()

#include <cstring>
#include <cerrno>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/mman.h>
#endif

// -------------------------------------------------------------------
// Windows implementation
// -------------------------------------------------------------------
#ifdef _WIN32

MappedFile::MappedFile(const std::string& path) {
    // Open file
    m_hFile = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (m_hFile == INVALID_HANDLE_VALUE) {
        DBG("[IO] Failed to open file: ", path, " (error ", GetLastError(), ")");
        return;
    }

    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(m_hFile, &fileSize)) {
        DBG("[IO] Failed to get file size: ", path, " (error ", GetLastError(), ")");
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        return;
    }
    m_file_size = static_cast<size_t>(fileSize.QuadPart);

    // Create mapping
    m_hMapping = CreateFileMapping(
        m_hFile,
        NULL,
        PAGE_READONLY,
        0, 0,
        NULL
    );
    if (m_hMapping == NULL) {
        DBG("[IO] Failed to create file mapping: ", path, " (error ", GetLastError(), ")");
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        return;
    }

    // Map view
    m_pMappedData = MapViewOfFile(
        m_hMapping,
        FILE_MAP_READ,
        0, 0,
        0  // map entire file
    );
    if (m_pMappedData == NULL) {
        DBG("[IO] Failed to map view of file: ", path, " (error ", GetLastError(), ")");
        CloseHandle(m_hMapping);
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        m_hMapping = NULL;
        return;
    }

    // Success
    DBG("[IO] Mapped view @ ", m_pMappedData, " size=", m_file_size, " bytes");
}

MappedFile::~MappedFile() {
    if (m_pMappedData != NULL) {
        UnmapViewOfFile(m_pMappedData);
        m_pMappedData = NULL;
    }
    if (m_hMapping != NULL) {
        CloseHandle(m_hMapping);
        m_hMapping = NULL;
    }
    if (m_hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
}

bool MappedFile::is_valid() const {
    return m_pMappedData != NULL;
}

std::span<const uint8_t> MappedFile::get_data() const {
    return std::span<const uint8_t>(
        static_cast<const uint8_t*>(m_pMappedData),
        m_file_size
    );
}

// -------------------------------------------------------------------
// POSIX implementation (Linux, Android, macOS, etc.)
// -------------------------------------------------------------------
#else

MappedFile::MappedFile(const std::string& path)
    : m_fd(-1), m_mapped(nullptr), m_file_size(0), m_valid(false) {
    // Open file
    m_fd = ::open(path.c_str(), O_RDONLY);
    if (m_fd == -1) {
        DBG("[IO] Failed to open file: ", path, " (", strerror(errno), ")");
        return;
    }

    // Get file size
    struct stat st;
    if (::fstat(m_fd, &st) != 0) {
        DBG("[IO] Failed to stat file: ", path, " (", strerror(errno), ")");
        ::close(m_fd);
        m_fd = -1;
        return;
    }
    m_file_size = static_cast<size_t>(st.st_size);

    // Memory-map
    m_mapped = ::mmap(nullptr, m_file_size, PROT_READ, MAP_PRIVATE, m_fd, 0);
    if (m_mapped == MAP_FAILED) {
        DBG("[IO] Failed to mmap file: ", path, " (", strerror(errno), ")");
        ::close(m_fd);
        m_fd = -1;
        m_mapped = nullptr;
        return;
    }

    DBG("[IO] Mapped view @ ", m_mapped, " size=", m_file_size, " bytes");
    m_valid = true;
}

MappedFile::~MappedFile() {
    if (m_mapped != nullptr && m_mapped != MAP_FAILED) {
        ::munmap(m_mapped, m_file_size);
        m_mapped = nullptr;
    }
    if (m_fd != -1) {
        ::close(m_fd);
        m_fd = -1;
    }
}

bool MappedFile::is_valid() const {
    return m_valid;
}

std::span<const uint8_t> MappedFile::get_data() const {
    return std::span<const uint8_t>(
        static_cast<const uint8_t*>(m_mapped),
        m_file_size
    );
}

#endif // _WIN32