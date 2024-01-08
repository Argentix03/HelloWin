// Process enumeration using the Restart Manager. The infamous "waiting for x to close before continuing"
// See https://learn.microsoft.com/en-us/windows/win32/rstmgr/using-restart-manager-with-a-primary-installer
// Secret sauce was also spilled at recon 2023

#include <windows.h>
#include <restartManager.h>
#include <Shlwapi.h>
#include <iostream>
#include <string>

#pragma warning(disable:4996)
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "Rstrtmgr.lib")
#pragma comment(lib, "Shlwapi.lib")


DWORD StartSession(DWORD* dwSession);


// Functions to return the WCHAR string from a value of RM enumerations
//
// Create a RM session 
//
DWORD StartSession(DWORD* dwSession)
{
	WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1];
	DWORD dwError = 1;
	//initialize the RM session's key
	memset(szSessionKey, 0, sizeof(szSessionKey));

	//starts the RM session and retrieves the session key
	dwError = RmStartSession(dwSession, 0, szSessionKey);

	if (dwError != ERROR_SUCCESS)
	{
		wprintf(L"[-] Error with RmStartSession: %d.\n", dwError);
		return dwError;
	}
	return 0;
}


const WCHAR* getRmRebootReason(RM_REBOOT_REASON RmRebootReason)
{
	switch (RmRebootReason)
	{
	case RmRebootReasonNone: return L"RmRebootReasonNone (A system restart is not required).";
	case RmRebootReasonPermissionDenied: return L"RmRebootReasonPermissionDenied (The current user does not have sufficient privileges to shut down one or more processes).";
	case RmRebootReasonSessionMismatch: return L"RmRebootReasonSessionMismatch (One or more processes are running in another Terminal Services session).";
	case RmRebootReasonCriticalProcess: return L"RmRebootReasonCriticalProcess (A system restart is needed because one or more processes to be shut down are critical processes).";
	case RmRebootReasonCriticalService: return L"RmRebootReasonCriticalService (A system restart is needed because one or more services to be shut down are critical services).";
	case RmRebootReasonDetectedSelf: return L"RmRebootReasonDetectedSelf (A system restart is needed because the current process must be shut down.)";
	default: return L"invalid value";
	}
}

const WCHAR* getRmAppType(RM_APP_TYPE RmAppType)
{
	switch (RmAppType)
	{
	case RmUnknownApp: return L"RmUnkownApp";
	case RmMainWindow: return L"RmMainWindow";
	case RmOtherWindow: return L"RmOtherWindow";
	case RmService: return L"RmService";
	case RmExplorer: return L"RmExplorer";
	case RmConsole: return L"RmConsole";
	case RmCritical: return L"RmCritical";
	default: return L"invalid value";
	}
}

const WCHAR* getRmAppStatus(RM_APP_STATUS RmAppStatus)
{
	switch (RmAppStatus)
	{
	case RmStatusUnknown: return L"RmStatusUnknown";
	case RmStatusRunning: return L"RmStatusRunning";
	case RmStatusStopped: return L"RmStatusStopped";
	case RmStatusStoppedOther: return L"RmStatusStoppedOther";
	case RmStatusRestarted: return L"RmStatusRestarted ";
	case RmStatusErrorOnStop: return L"RmStatusErrorOnStop";
	case RmStatusErrorOnRestart: return L"RmStatusErrorOnRestart";
	case RmStatusShutdownMasked: return L"RmStatusShutdownMasked";
	case RmStatusRestartMasked: return L"RmStatusRestartMasked ";
	default: return L"invalid value";
	}
}

const WCHAR* getRmAppRestartable(BOOL RmAppType)
{
	switch (RmAppType)
	{
	case 0: return L"false";
	case 1: return L"true";
	default: return L"invalid value";
	}
}

void DisplayInfo(RM_PROCESS_INFO rgpi)
{

	if (rgpi.ApplicationType == RmService)
	{
		wprintf( L"\n --- Service: ");
		wprintf( L"%ws ", rgpi.strServiceShortName);
		wprintf( L"---- \n");
	}
	else
	{
		wprintf( L"\n --- Process: ");
		wprintf( L"%ws ", rgpi.strAppName);
		wprintf( L"---- \n");
	}

	wprintf( L"| PID associated:");
	wprintf( L" %d\n", rgpi.Process.dwProcessId);
	wprintf( L"| Application Type:");
	wprintf( L" %s\n", getRmAppType(rgpi.ApplicationType));
	wprintf( L"| Application status:");
	wprintf( L" %s\n", getRmAppStatus((RM_APP_STATUS)rgpi.AppStatus));
	wprintf( L"| Application is restartable:");
	wprintf( L" %s\n", getRmAppRestartable(rgpi.bRestartable));

	return;
}

//
//	Function to determine if one of the affected app is currently stopped
//	Returns TRUE if at least one app is currently runnin
BOOL AreAffectedAppsRunning(RM_PROCESS_INFO* RMProcInfo, DWORD nProcInfo)
{
	for (UINT i = 0; i < nProcInfo; i++)
	{
		// If the affected app is running
		if (RMProcInfo[i].AppStatus != RmStatusStopped && RMProcInfo[i].AppStatus != RmStatusStoppedOther)
			return TRUE;
	}

	return FALSE;
}

// Function to check a single executable for affected applications
void CheckExecutableForAffectedApps(const std::wstring& exePath) {
    DWORD dwSession;
    if (StartSession(&dwSession) == 0) {
		char ShutDown = 'n';
		UINT nProcInfoNeeded, nProcInfo = 0;
		DWORD dwReason, dwError = 1;
		HANDLE hTargetProces = NULL;
		RM_PROCESS_INFO* RMProcInfo = NULL;

		LPCWSTR filePath[1] = { exePath.c_str() };

		// Register the file to check with the RM_UNIQUE_PROCESS array
		dwError = RmRegisterResources(dwSession, 1, filePath, 0, NULL, 0, NULL);

		// Retrieves the appropriate number of affected apps & subsequently allocate the RM_PROCESS_INFO structures
		dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);
		nProcInfo = nProcInfoNeeded;
		RMProcInfo = (RM_PROCESS_INFO*)calloc(nProcInfoNeeded + 1, sizeof(RM_PROCESS_INFO));

		// Retrieves the list of processes using the file
		dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, RMProcInfo, &dwReason);
		if (dwError != ERROR_SUCCESS)
		{
			if (dwError != ERROR_SHARING_VIOLATION)
			{
				wprintf(L"[-] Error with RmGetList():%d, for path:%ws.\n", dwError, exePath.c_str());
			}
		}

		// If no process is currently using the resource
		if (nProcInfo != 0)
		{
			printf("\n ------- Applications using the file: ");
			wprintf(L"%ws.\n", exePath.c_str());
			for (UINT i = 0; i < nProcInfo; i++)
			{
				DisplayInfo(RMProcInfo[i]);
			}
		}

        dwError = RmEndSession(dwSession);
        if (dwError != ERROR_SUCCESS) {
            std::wcerr << L"[-] Error with RmEndSession: " << dwError << std::endl;
        }
    }
}

// Function to scan a directory for executables and check them for affected applications
void ScanDirectoryForExecutables(const std::wstring& directory) {
    WIN32_FIND_DATA findFileData;
    std::wstring searchPath = directory + L"\\*.exe";
    HANDLE hFind = FindFirstFile(searchPath.c_str(), &findFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring exePath = directory + L"\\" + findFileData.cFileName;
            CheckExecutableForAffectedApps(exePath);
        } while (FindNextFile(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
}

// Recursive function to scan a directory and its subdirectories for executables
void ScanDirectoryRecursively(const std::wstring& directory) {
	WIN32_FIND_DATA findFileData;
	std::wstring searchPath = directory + L"\\*.*";
	HANDLE hFind = FindFirstFile(searchPath.c_str(), &findFileData);

	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (wcscmp(findFileData.cFileName, L".") == 0 || wcscmp(findFileData.cFileName, L"..") == 0) {
				continue;  // Skip current directory and parent directory entries
			}

			std::wstring filePath = directory + L"\\" + findFileData.cFileName;

			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				// If it's a directory, recursively scan it
				ScanDirectoryRecursively(filePath);
			}
			else {
				// If it's a file, check if it's an executable and then check for affected apps
				if (PathMatchSpec(filePath.c_str(), L"*.exe")) {
					CheckExecutableForAffectedApps(filePath);
				}
			}
		} while (FindNextFile(hFind, &findFileData) != 0);
		FindClose(hFind);
	}
}

int main() {
	// Specify the root directory to start scanning
	std::wstring rootDirectory = L"C:\\";  // Change this to the desired starting directory

	// Scan the specified directory and its subdirectories for executables and check them for affected applications
	ScanDirectoryRecursively(rootDirectory);

	return 0;
}



