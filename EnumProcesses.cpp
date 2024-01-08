// Process enumeration using psapi. very classic example.
#include <windows.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <algorithm>

bool EnumerateProcesses(std::vector<DWORD>& processList) {
    DWORD processes[1024];
    DWORD bytesReturned;

    if (EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        DWORD numProcesses = bytesReturned / sizeof(DWORD);

        processList.reserve(numProcesses);

        for (DWORD i = 0; i < numProcesses; i++) {
            processList.push_back(processes[i]);
        }

        return true;
    }

    return false;
}

void GetProcessName(DWORD processID, std::wstring& processName) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess) {
        WCHAR szProcessName[MAX_PATH];
        if (GetModuleBaseName(hProcess, NULL, szProcessName, sizeof(szProcessName) / sizeof(WCHAR))) {
            processName = szProcessName;
        }
        CloseHandle(hProcess);
    }
}

int main() {
    std::vector<DWORD> processList;

    if (EnumerateProcesses(processList)) {
        std::sort(processList.begin(), processList.end());

        std::wcout << L"List of running processes:" << std::endl;
        for (const DWORD& pid : processList) {
            std::wstring processName;
            GetProcessName(pid, processName);
            std::wcout << L"PID: " << pid << L" Name: " << processName << std::endl;
        }
    }
    else {
        std::cerr << "Failed to enumerate processes." << std::endl;
    }

    return 0;
}
