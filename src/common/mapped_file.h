#pragma once
#include <string>
#include <span>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#else
// Linux/POSIX
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

class MappedFile {
public:
    MappedFile(const std::string& path);
    ~MappedFile();

    // Disable copy/move for simplicity
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    bool is_valid() const;
    std::span<const uint8_t> get_data() const;

private:
#ifdef _WIN32
    HANDLE m_hFile = INVALID_HANDLE_VALUE;
    HANDLE m_hMapping = NULL;
    LPCVOID m_pMappedData = NULL;
#else
    int m_fd = -1;
    void* m_pMappedData = nullptr;
#endif
    size_t m_file_size = 0;
};