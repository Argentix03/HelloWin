#include <Windows.h>
#include <stdio.h>

bool KillProcess(int);

int main(int argc, const char* argv[])
{
    if (argc < 2) {
        printf("Usage: KillProcess.exe <pid>");
        return 0;
    }

    int pid = atoi(argv[1]);

    bool success = KillProcess(pid);
    return success;
}

bool KillProcess(int pid)
{
    HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess)
        return false;

    BOOL result = ::TerminateProcess(hProcess, 1); // kill with exit code 1
    ::CloseHandle(hProcess);

    return result != FALSE;
}

