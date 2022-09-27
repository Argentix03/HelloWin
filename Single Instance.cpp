#include <stdio.h>
#include <Windows.h>
#include "string"
#include "stdafx.h"
#define WM_NOTIFY_INSTANCE (WM_USER + 100)

using namespace std;

void NotifyOtherInstance();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPSTR /*lpstrCmdLine*/, int /*nCmdShow*/)
{
    HANDLE hMutex = ::CreateMutex(nullptr, FALSE, L"SingleInstanceMutex");
    if (!hMutex) {
        std::wstring errorText = L"Failded to create mutex : (ERROR: ";
        errorText += GetLastError();
        ::MessageBox(nullptr, errorText.c_str(), L"Single Instance", MB_OK);
        return 0;
    }

    if (::GetLastError() == ERROR_ALREADY_EXISTS) {
        NotifyOtherInstance();
        return 0;
    }

    HRESULT hRes = ::CoInitialize(nullptr);
    ATLASSERT()
}

void NotifyOtherInstance() 
{
    HWND hWnd = FindWindow(nullptr, L"Single Instance");
    if (!hWnd) {
        ::MessageBox(nullptr, L"Failed to locate window of other instance", L"Single Instance", MB_OK);
        return;
    }
    ::PostMessage(hWnd, WM_NOTIFY_INSTANCE, ::GetCurrentProcessId(), 0);
    ::ShowWindow(hWnd, SW_NORMAL);
    ::SetForegroundWindow(hWnd);
}
