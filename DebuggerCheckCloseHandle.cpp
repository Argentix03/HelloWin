#include <Windows.h>
#include <stdio.h>

int main(int argc, const char* argv[])
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
    SetHandleInformation(hProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    MessageBox(nullptr, L"SetHandleInformation(hProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);", L"handle information set", MB_OK);
    __try {
        if (!CloseHandle(hProcess)) {
            printf("Failed to close handle\n");
            printf("Debugger not detected (with this technique)\n");
        };
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("Debugger detected\n");
    }

    return 0;
}



