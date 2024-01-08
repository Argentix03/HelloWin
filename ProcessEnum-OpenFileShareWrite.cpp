// process enumeration based on access share violation in executables. most of the time this means it is loaded as a module in a processes.
// can have a bunch of false positives but still a cool idea. iterate through all executables on the system and check access. 
// for best results run as TrustedInstaller but better just avoid this stupid way in the first place.
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

void EnumerateExecutableFiles(const std::wstring& directory) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((directory + L"\\*.*").c_str(), &findFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                (findFileData.cFileName[0] != '.') &&
                (wcsstr(findFileData.cFileName, L".exe") != nullptr)) {
                std::wstring filePath = directory + L"\\" + findFileData.cFileName;

                HANDLE hFile = CreateFileW(
                    filePath.c_str(),
                    GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                );

                if (hFile != INVALID_HANDLE_VALUE) {
                    // Executable not currently mapped
                    CloseHandle(hFile);
                }
                // another process has mapped this executable. 
                else if (GetLastError() == ERROR_SHARING_VIOLATION) {
                    std::wcout << L"Another process has mapped this executable: " << filePath << std::endl;
                }
                else {
                    DWORD errorCode = GetLastError();
                    if (errorCode != ERROR_ACCESS_DENIED) {
                        std::wcerr << L"Error occurred: " << filePath << L" Error Code: " << errorCode << std::endl;
                    }
                }
            }
            else if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                (findFileData.cFileName[0] != '.')) {
                // Recursive call to enumerate files in subdirectories
                EnumerateExecutableFiles(directory + L"\\" + findFileData.cFileName);
            }
        } while (FindNextFile(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
}

int main() {
    std::wstring directoryToSearch = L"C:\\";  // Start from the root directory
    EnumerateExecutableFiles(directoryToSearch);
    return 0;
}
