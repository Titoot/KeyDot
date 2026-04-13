#pragma once

#include <cstdint>
#include <span>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

class MappedFile {
public:
    MappedFile(const std::string& path);
    ~MappedFile();

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    bool is_valid() const;
    std::span<const uint8_t> get_data() const;

private:
#ifdef _WIN32
    HANDLE m_hFile = INVALID_HANDLE_VALUE;
    HANDLE m_hMapping = NULL;
    LPCVOID m_pMappedData = NULL;
    size_t m_file_size = 0;
#else
    int m_fd = -1;
    void* m_pMappedData = nullptr;
    size_t m_file_size = 0;
#endif
};
