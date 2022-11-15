#include <Windows.h>
#include <WtsApi32.h>
#include <stdio.h>
#pragma comment(lib, "wtsapi32")

int main()
{
    // Process Info struct for process creation
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.wShowWindow = TRUE;
    
    // Session handles
    HANDLE hUsertoken;
    DWORD sessionId;
    sessionId = WTSGetActiveConsoleSessionId();
    WTSQueryUserToken(sessionId, &hUsertoken);
    WCHAR desk[] = L"WinSta0\Default";
    si.lpDesktop = desk;
    CreateProcessAsUser(hUsertoken, TEXT("C:\\Windows\\System32\\cmd.exe"), 0, 0, 0, 0, 0, 0, 0, &si, &pi);

    return 0;
}
