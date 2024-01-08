// Process enumeration using WTS (Windows Terminal Services). Credit: Pavel Yosifovich.
// See Windows System Programming examples for Process Enumeration.
// Also see https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumerateprocessesa

#include <stdio.h>
#include <Windows.h>
#include <wtsapi32.h>
#include <string>

#pragma comment(lib, "wtsapi32.lib")

bool EnableDebugPriv() {
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return false;

	TOKEN_PRIVILEGES tprivs;
	tprivs.PrivilegeCount = 1;
	tprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tprivs.Privileges[0].Luid))
		return false;

	BOOL success = AdjustTokenPrivileges(hToken, FALSE, &tprivs, sizeof(tprivs), nullptr, nullptr);
	CloseHandle(hToken);

	return success && GetLastError() == ERROR_SUCCESS;
}

std::wstring GetUserNameFromSid(PSID sid) {
	if (sid == nullptr)
		return L"";

	WCHAR name[32], domain[32];
	DWORD lname = _countof(name), ldomain = _countof(domain);
	SID_NAME_USE use;
	if (!LookupAccountSid(nullptr, sid, name, &lname, domain, &ldomain, &use))
		return L"";

	return std::wstring(domain) + L"\\" + name;
}

int main() {
	EnableDebugPriv();

	DWORD level = 1;
	WTS_PROCESS_INFO_EX* info;
	DWORD count;
	BOOL success = WTSEnumerateProcessesEx(WTS_CURRENT_SERVER_HANDLE, &level, WTS_ANY_SESSION, (LPWSTR*)&info, &count);
	if (!success)
		return 1;

	for (DWORD i = 0; i < count; i++) {
		PWTS_PROCESS_INFO_EX p = info + i;
		printf("PID: %6u\tThread: %3u\tSession: %u %ws (username: %ws)\n",
			p->ProcessId, p->NumberOfThreads, p->SessionId, p->pProcessName, GetUserNameFromSid(p->pUserSid).c_str());
	}

	WTSFreeMemoryEx(WTSTypeProcessInfoLevel1, info, count);
	return 0;
}