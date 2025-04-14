// Using fake Registry hive for process enumeration. Performance data is not actually stored in the registry.
// see https://learn.microsoft.com/en-us/windows/win32/perfctrs/using-the-registry-functions-to-consume-counter-data
// and https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexa
// dunno how to parse it...   text values unicode of process named and pids (as text too) has been spotted inside. Hard to find in strings because i output as a unicode buffer char by char as unicde each char (it comes out double padded for single byte chars)

#include <Windows.h>
#include <iostream>

#define TOTALBYTES 8192
#define BYTEINCREMENT 4096

// Define the performance data block structure
#pragma pack(push, 1)
struct PerfDataBlock {
    DWORD Signature;
    DWORD LittleEndian;
    DWORD Version;
    DWORD Revision;
    DWORD TotalByteLength;
    DWORD HeaderLength;
    DWORD NumObjectTypes;
    LONG DefaultObject;
    SYSTEMTIME SystemTime;
    LARGE_INTEGER PerfTime;
    LARGE_INTEGER PerfFreq;
    LARGE_INTEGER CounterTime;
    LARGE_INTEGER CounterFreq;
};
#pragma pack(pop)

int main() {
    DWORD bufferSize = TOTALBYTES;
    DWORD cbData;
    LONG result;

    // Allocate an initial buffer
    BYTE* perfDataBuffer = new BYTE[bufferSize];

    cbData = bufferSize;

    std::wcout << L"Retrieving the data..." << std::endl;

    result = RegQueryValueEx(HKEY_PERFORMANCE_DATA, L"Global", nullptr, nullptr, perfDataBuffer, &cbData);

    while (result == ERROR_MORE_DATA) {
        // Get a larger buffer
        bufferSize += BYTEINCREMENT;
        delete[] perfDataBuffer;
        perfDataBuffer = new BYTE[bufferSize];
        cbData = bufferSize;

        std::wcout << L".";
        std::cout.flush();

        result = RegQueryValueEx(HKEY_PERFORMANCE_DATA, L"Global", nullptr, nullptr, perfDataBuffer, &cbData);
    }

    if (result == ERROR_SUCCESS) {
        std::wcout << L"\n\nFinal buffer size is " << bufferSize << std::endl;
    }
    else {
        std::wcerr << L"\nRegQueryValueEx failed with error code: " << result << std::endl;
    }

    // Interpret the performance data block
    PerfDataBlock* perfData = reinterpret_cast<PerfDataBlock*>(perfDataBuffer);

    std::cout << "Signature: " << perfData->Signature << std::endl;
    std::cout << "Version: " << perfData->Version << std::endl;
    std::cout << "Revision: " << perfData->Revision << std::endl;
    std::cout << "Total Byte Length: " << perfData->TotalByteLength << std::endl;
    std::cout << "Number of Object Types: " << perfData->NumObjectTypes << std::endl;

    // Spam warning
    std::cout << "Proccess names are in there, but i how to parse this shit?" << std::endl;
    Sleep(2000);
    std::cout << "So heres a dump..." << std::endl;
    Sleep(4000);

    // Print the data as ASCII characters
    for (DWORD i = 0; i < cbData; ++i) {
        char ch = static_cast<char>(perfDataBuffer[i]);
        std::cout << ch;   // this comes out as double wide unicode.  "Total" becomes 54 00 00 00 6F 00 00 00 74 00 00 00 61 00 00 00 6C
    }

    // Clean up the allocated buffer
    delete[] perfDataBuffer;

    return 0;
}


express vpn