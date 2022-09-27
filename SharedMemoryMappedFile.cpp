#include <Windows.h>
#include <stdio.h>
#define MEMSIZE (1 << 12)

void write(HANDLE hSharedMem, WCHAR data[]);
WCHAR* read(HANDLE hSharedMem);

int main(int argc, const char* argv[])
{
    if (argc < 2) {
        printf("Usage: SharedMemoryMappedFile.exe <1|2>");
        return 0;
    }

    HANDLE hSharedMem = ::CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, MEMSIZE, L"SharedMemory123");
    if (!hSharedMem) {
        printf("Failed to get handle from CreateFileMapping (ERROR: %d)\n", GetLastError());
        return 0;
    }

    if (atoi(argv[1]) == 1) {
        WCHAR data[] = L"testing data";
        write(hSharedMem, data);
    }
    if (atoi(argv[1]) == 2) {
        WCHAR* readData = read(hSharedMem);
        printf("Data in buffer: %ws\n", readData);
    }

    MessageBox(nullptr, L"Press ok to exit", L"Wait", MB_OK);
    return 0;
}

void write(HANDLE hSharedMem, WCHAR data[])
{
    printf("write 1\n");
    void* buffer = ::MapViewOfFile(hSharedMem, FILE_MAP_WRITE, 0, 0, 0);
    if (!buffer) {
        printf("Failed to get pointer from MapViewOfFile (ERROR: %d) in write()\n", GetLastError());
        return;
    }

    ::wcscpy_s((PWSTR)buffer, MEMSIZE/2, data);
    printf("Written data in buffer: %ws\n", data);

    ::UnmapViewOfFile(buffer);
    ::CloseHandle(hSharedMem);

    return;
}

WCHAR* read(HANDLE hSharedMem)
{
    void* buffer = ::MapViewOfFile(hSharedMem, FILE_MAP_READ, 0, 0, 0);
    if (!buffer) {
        printf("Failed to get pointer from MapViewOfFile (ERROR: %d) in read()\n", GetLastError());
        return nullptr;
    }

    WCHAR data[MEMSIZE];
    ::wcscpy_s(data, MEMSIZE/2, (PWSTR)buffer);
    printf("Data in buffer: %ws\n", data);

    ::UnmapViewOfFile(buffer);
    ::CloseHandle(hSharedMem);

    return data;
}

