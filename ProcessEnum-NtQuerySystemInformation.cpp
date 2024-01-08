// The infamous undocumented documented information classes...
// reserved buffers -> bigger structs -> better info classes!

#include <Windows.h>
#include <iostream>
#include <Winternl.h>
#include <ntstatus.h>
#include <vector>
#include <algorithm>
#include <iomanip>

#pragma comment(lib, "ntdll")

// Define the NtQuerySystemInformation function prototype
EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

// Macro for converting handles to ULONG
#ifndef HandleToUlong
#define HandleToUlong( h ) ((ULONG)(ULONG_PTR)(h))
#endif

// Structure to hold process information
struct ProcessInfo {
    ULONG PID;
    std::wstring ProcessName;
    ULONG SessionID;
};

// Comparison function for sorting by PID
bool CompareByPID(const ProcessInfo& a, const ProcessInfo& b) {
    return a.PID < b.PID;
}

// Function to list all processes
void ListProcesses() {
    NTSTATUS status;
    ULONG bufferSize = 0;

    // Get the required buffer size
    status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        std::cerr << "NtQuerySystemInformation failed with status: " << std::hex << status << std::endl;
        return;
    }

    // Allocate a buffer of the required size
    PVOID buffer = ::operator new(bufferSize);
    if (!buffer) {
        std::cerr << "Failed to allocate memory for process information." << std::endl;
        return;
    }

    // Retrieve process information
    status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, nullptr);
    if (NT_SUCCESS(status)) {
        PSYSTEM_PROCESS_INFORMATION processInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
        std::vector<ProcessInfo> processList;

        while (processInfo) {
            ProcessInfo pInfo;
            pInfo.PID = HandleToUlong(processInfo->UniqueProcessId);
            pInfo.ProcessName = processInfo->ImageName.Buffer ? processInfo->ImageName.Buffer : L"";
            pInfo.SessionID = processInfo->SessionId;

            processList.push_back(pInfo);

            if (!processInfo->NextEntryOffset)
                break;

            processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(processInfo) + processInfo->NextEntryOffset);
        }

        // Sort the process list by PID
        std::sort(processList.begin(), processList.end(), CompareByPID);

        // Display the sorted list in a table
        std::wcout << std::left << std::setw(10) << L"PID" << std::setw(30) << L"Process Name" << L"Session ID" << std::endl;
        std::wcout << std::setfill(L'-') << std::setw(50) << L"" << std::setfill(L' ') << std::endl;

        for (const ProcessInfo& pInfo : processList) {
            std::wcout << std::left << std::setw(10) << pInfo.PID << std::setw(30) << pInfo.ProcessName << pInfo.SessionID << std::endl;
        }
    }
    else {
        std::cerr << "NtQuerySystemInformation failed with status: " << std::hex << status << std::endl;
    }

    // Clean up the allocated buffer
    ::operator delete(buffer);
}

int main() {
    ListProcesses();
    return 0;
}
