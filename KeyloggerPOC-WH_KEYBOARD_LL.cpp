#include <windows.h>
#include <iostream>

HHOOK g_hHook = NULL;

// Low-level keyboard hook callback
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    // Must always call next hook if nCode < 0
    if (nCode < 0) {
        return CallNextHookEx(g_hHook, nCode, wParam, lParam);
    }

    // Only process the message if nCode == HC_ACTION
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* kbStruct = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        // We're interested in key-down events
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            DWORD vkCode = kbStruct->vkCode;  // Virtual Key code

            std::cout << std::hex << "VK Code: 0x"
                << vkCode << std::dec << std::endl;

            // Example: if ESC is pressed, post a quit message
            if (vkCode == VK_ESCAPE) {
                std::cout << "ESC pressed. Exiting..." << std::endl;
                PostQuitMessage(0);
            }
        }
    }

    // Pass the event to the next hook in the chain
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

int main()
{
    std::cout << "Installing WH_KEYBOARD_LL hook..." << std::endl
        << "Press ESC to exit." << std::endl;

    // Install the global low-level keyboard hook
    // (Passing 0 as thread id => global in this user session)
    g_hHook = SetWindowsHookExW(
        WH_KEYBOARD_LL,         // Hook type
        KeyboardProc,   // Callback
        GetModuleHandleW(NULL), // Handle to our module
        0                       // 0 => global hook in this user session
    );

    if (!g_hHook) {
        DWORD error = GetLastError();
        std::cerr << "Failed to install WH_KEYBOARD_LL hook. Error: "
            << error << std::endl
            << "Press ENTER to exit." << std::endl;
        std::cin.get();
        return 1;
    }

    std::cout << "Hook installed successfully." << std::endl;

    // We need a standard message loop on this thread
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Cleanup
    std::cout << "Unhooking before exit..." << std::endl;
    if (g_hHook) {
        UnhookWindowsHookEx(g_hHook);
        g_hHook = NULL;
    }

    return 0;
}
