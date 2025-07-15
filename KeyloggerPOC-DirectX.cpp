#define DIRECTINPUT_VERSION 0x0800 // Use DirectInput 8
#include <dinput.h>
#include <iostream>
#include <vector>
#include <windows.h> 
#include <initguid.h> 

// Linker dependencies
#pragma comment(lib, "dinput8.lib")
#pragma comment(lib, "dxguid.lib")

int main() {
    HINSTANCE hInstance = GetModuleHandle(NULL);
    LPDIRECTINPUT8        g_pDI = NULL;
    LPDIRECTINPUTDEVICE8  g_pKeyboard = NULL;
    char                  buffer[256]; // DirectInput keyboard state buffer
    char                  prev_buffer[256] = { 0 }; // To detect key presses

    // Create a dummy window (required for SetCooperativeLevel)
    LPCWSTR CLASS_NAME = L"DInputDummyWindowClass";
    WNDCLASS wc = {};
    wc.lpfnWndProc = DefWindowProc; // Default handler is fine
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);
    HWND hwnd = CreateWindowEx(0, CLASS_NAME, L"DInput Dummy", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);
    if (!hwnd) {
        std::cerr << "Dummy window creation failed!" << std::endl;
        return 1;
    }


    // Initialize DirectInput
    if (FAILED(DirectInput8Create(hInstance, DIRECTINPUT_VERSION, IID_IDirectInput8, (VOID**)&g_pDI, NULL))) {
        std::cerr << "DirectInput8Create failed!" << std::endl;
        DestroyWindow(hwnd);
        return 1;
    }

    // Create the keyboard device
    if (FAILED(g_pDI->CreateDevice(GUID_SysKeyboard, &g_pKeyboard, NULL))) {
        std::cerr << "CreateDevice (Keyboard) failed!" << std::endl;
        g_pDI->Release();
        DestroyWindow(hwnd);
        return 1;
    }

    // Set the data format
    if (FAILED(g_pKeyboard->SetDataFormat(&c_dfDIKeyboard))) {
        std::cerr << "SetDataFormat failed!" << std::endl;
        g_pKeyboard->Release();
        g_pDI->Release();
        DestroyWindow(hwnd);
        return 1;
    }

    // Set the cooperative level (background, non-exclusive)
    // DISCL_BACKGROUND requires a window handle (even a dummy one)
    if (FAILED(g_pKeyboard->SetCooperativeLevel(hwnd, DISCL_BACKGROUND | DISCL_NONEXCLUSIVE))) {
        std::cerr << "SetCooperativeLevel failed!" << std::endl;
        g_pKeyboard->Release();
        g_pDI->Release();
        DestroyWindow(hwnd);
        return 1;
    }

    // Acquire the keyboard
    HRESULT hr = g_pKeyboard->Acquire();
    if (FAILED(hr) && (hr == DIERR_OTHERAPPHASPRIO || hr == DIERR_NOTACQUIRED)) {
        std::cerr << "Could not acquire keyboard initially. May need focus or retry." << std::endl;
        // Continue attempting to acquire in the loop
    }
    else if (FAILED(hr)) {
        std::cerr << "Acquire failed initially with error: " << hr << std::endl;
        g_pKeyboard->Release();
        g_pDI->Release();
        DestroyWindow(hwnd);
        return 1;
    }


    std::cout << "DirectInput Initialized. Polling for key presses..." << std::endl;

    // Polling loop, no exit condition
    while (true) {
        hr = g_pKeyboard->GetDeviceState(sizeof(buffer), (LPVOID)&buffer);

        if (FAILED(hr)) {
            // If input is lost or not acquired, try to reacquire
            if (hr == DIERR_INPUTLOST || hr == DIERR_NOTACQUIRED) {
                hr = g_pKeyboard->Acquire();
                if (FAILED(hr)) {
                    // std::cerr << "Re-acquire failed!" << std::endl; // A bit noisy
                    Sleep(100); // Wait before retrying acquire
                    continue; // Skip processing this iteration
                }
                else {
                    // std::cout << "Re-acquired keyboard." << std::endl;
                }
            }
            else {
                std::cerr << "GetDeviceState failed with unknown error: " << hr << std::endl;
                break; // Exit on other errors
            }
        }
        else {
            // Process keyboard state
            for (int i = 0; i < 256; ++i) {
                // Check if key is pressed now (high bit set) and was NOT pressed before
                if ((buffer[i] & 0x80) && !(prev_buffer[i] & 0x80)) {
                    std::cout << "DIK Code Pressed: 0x" << std::hex << i << std::endl;
                    // Can map DIK_* codes (dinput.h) to VK codes or characters here
                    if (i == DIK_ESCAPE) { // Exit condition
                        break;
                    }
                }
            }
            // Store current state for next comparison
            memcpy(prev_buffer, buffer, sizeof(buffer));
        }

        // Need message processing for the dummy window and cooperative level
        MSG msg;
        if (PeekMessage(&msg, hwnd, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }


        Sleep(20); // To avoid 100% CPU usage
    }

    return 0;
}