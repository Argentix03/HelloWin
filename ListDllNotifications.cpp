// Listing dll notification entries from proccess' PEB

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

//redefine UNICODE_STR struct
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

//redefine PEB_LDR_DATA struct
typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//redefine PEB_FREE_BLOCK struct
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

//redefine PEB struct
typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    _PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

// structure and definitions taken from:
// https://modexp.wordpress.com/2020/08/06/windows-data-structures-and-callbacks-part-1/

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG           Flags;             // Reserved.
    PUNICODE_STR FullDllName;       // The full path name of the DLL module.
    PUNICODE_STR BaseDllName;       // The base file name of the DLL module.
    PVOID           DllBase;           // A pointer to the base address for the DLL in memory.
    ULONG           SizeOfImage;       // The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG           Flags;             // Reserved.
    PUNICODE_STR FullDllName;       // The full path name of the DLL module.
    PUNICODE_STR BaseDllName;       // The base file name of the DLL module.
    PVOID           DllBase;           // A pointer to the base address for the DLL in memory.
    ULONG           SizeOfImage;       // The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA   Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG                       NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA  NotificationData,
    PVOID                       Context);

typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
    LIST_ENTRY                     List;
    PLDR_DLL_NOTIFICATION_FUNCTION Callback;
    PVOID                          Context;
} LDR_DLL_NOTIFICATION_ENTRY, * PLDR_DLL_NOTIFICATION_ENTRY;

typedef NTSTATUS(NTAPI* _LdrRegisterDllNotification) (
    ULONG                          Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID                          Context,
    PVOID* Cookie);

typedef NTSTATUS(NTAPI* _LdrUnregisterDllNotification)(PVOID Cookie);

typedef NTSTATUS(NTAPI* NtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);



VOID Callback(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
    return;
}

// Register one notification to get its entry and traverse one backwards 
PLIST_ENTRY GetDllNotificationListHead() {
    PLIST_ENTRY listHead = 0;

    HMODULE hNtdll = GetModuleHandleA("NTDLL.dll");
    if (hNtdll != NULL) {
        _LdrRegisterDllNotification pLdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");
        _LdrUnregisterDllNotification pLdrUnregisterDllNotification = (_LdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

        PLDR_DLL_NOTIFICATION_ENTRY notification;
        NTSTATUS status = pLdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)Callback, NULL, (PVOID *)&notification);
        if (status == 0) {
            listHead = notification->List.Flink;
            pLdrUnregisterDllNotification(notification);
        }
    }

    return listHead;
}

// Count the number of notification routines in a process's Dll Notification List
int CountNotificationRoutines(HANDLE hProc, LPVOID remoteHeadAddress) {
    int count = 0;

    BYTE* entry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));
    if (entry == NULL) {
        return -1; // Error allocating memory
    }

    ReadProcessMemory(hProc, remoteHeadAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    LPVOID currentEntryAddress = remoteHeadAddress;

    do {
        count++;

        currentEntryAddress = ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->List.Flink;
        ReadProcessMemory(hProc, currentEntryAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    } while ((PLIST_ENTRY)currentEntryAddress != remoteHeadAddress);

    free(entry);

    // minus the head entry that apppears everywhere regardless of registered notification.
    return count - 1;
}

// Print LdrpDllNotificationList of a remote process
void PrintDllNotificationList(HANDLE hProc, LPVOID remoteHeadAddress) {

    // Allocate memory buffer for LDR_DLL_NOTIFICATION_ENTRY
    BYTE* entry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    // Read the head entry from the remote process
    ReadProcessMemory(hProc, remoteHeadAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    LPVOID currentEntryAddress = remoteHeadAddress;
    do {

        // print the addresses of the LDR_DLL_NOTIFICATION_ENTRY and its callback function
        // dont print the head as its irrelevant here
        if ((PLIST_ENTRY)currentEntryAddress != remoteHeadAddress)
            printf("\tPEB Notification list entry: 0x%p\n\tCallback function: 0x%p\n", currentEntryAddress, ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->Callback);

        // Get the address of the next callback in the list
        currentEntryAddress = ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->List.Flink;

        // Read the next callback in the list
        ReadProcessMemory(hProc, currentEntryAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    } while ((PLIST_ENTRY)currentEntryAddress != remoteHeadAddress); // Stop when we reach the head of the list again

    free(entry);

    printf("\n");
}

// Function to get the process name given a process ID
void GetProcessName(DWORD processId, char* buffer, DWORD bufferSize) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProc != NULL) {
        if (K32GetModuleBaseNameA(hProc, NULL, buffer, bufferSize) == 0) {
            strcpy(buffer, "Unknown");
        }
        CloseHandle(hProc);
    }
    else {
        strcpy(buffer, "Unknown");
    }
}

int main()
{
    // Get local LdrpDllNotificationList head address
    LPVOID headAddress = (LPVOID)GetDllNotificationListHead();
    printf("PEB LdrpDllNotificationList head: 0x%p\n", headAddress);

    // Iterate through all processes on your machine
    DWORD processIds[1024];
    DWORD bytesReturned;
    if (EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        int numProcesses = bytesReturned / sizeof(DWORD);

        for (int i = 0; i < numProcesses; i++) {
            HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processIds[i]);
            if (hProc != NULL) {
                char processName[MAX_PATH];
                GetProcessName(processIds[i], processName, sizeof(processName));

                // Skip printing if the process name is "Unknown"
                if (strcmp(processName, "Unknown") != 0) {
                    // Count and print the number of notification routines for each process
                    int notificationRoutineCount = CountNotificationRoutines(hProc, headAddress);
                    if (notificationRoutineCount) {
                        printf("Process Name: %s (PID: %d)\n", processName, processIds[i]);
                        printf("Number of Notification Routines: %d\n", notificationRoutineCount);
                        PrintDllNotificationList(hProc, headAddress);
                    }
                    else if (notificationRoutineCount == -1) {
                        printf("Error counting notification routines.\n");
                    }
                }

                CloseHandle(hProc);
            }
        }
    }

    return 0;
}
