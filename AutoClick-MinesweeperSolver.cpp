#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include <vector>
#include <iostream>
#include <thread>
#include <chrono>

struct CoVal {
    int x;
    int y;
    int val;
};

std::vector<CoVal> coValArray;

DWORD GetProcessIdByWindowTitle(const std::wstring& windowTitle) {
    HWND hwnd = FindWindow(NULL, windowTitle.c_str());
    if (hwnd == NULL) {
        return 0;
    }

    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);
    return processId;
}

void ClickCell(int x, int y) {
    SetCursorPos(x, y);
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
}

void AutoSolver(HWND hwnd, int topLeftX, int topLeftY) {
    for (const auto& tile : coValArray) {
        if (tile.val == 0) {
            int tileX = topLeftX + (tile.x * 16);
            int tileY = topLeftY + (tile.y * 16);
            ClickCell(tileX, tileY);
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
        }
    }
}

void ReadWinmineMemory(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::wcerr << L"Failed to open process" << std::endl;
        return;
    }

    uintptr_t baseAddress = 0x01000000;
    uintptr_t mineStructAddress = baseAddress + 0x5330;

    DWORD bombCount, sizeX, sizeY;
    ReadProcessMemory(hProcess, (LPCVOID)(mineStructAddress), &bombCount, sizeof(DWORD), NULL);
    ReadProcessMemory(hProcess, (LPCVOID)(mineStructAddress + 4), &sizeX, sizeof(DWORD), NULL);
    ReadProcessMemory(hProcess, (LPCVOID)(mineStructAddress + 8), &sizeY, sizeof(DWORD), NULL);

    std::wcout << L"[+] Winmine board state.." << std::endl;
    std::wcout << L"    |-> Bombs  : " << bombCount << std::endl;
    std::wcout << L"    |-> Size-X : " << sizeX << std::endl;
    std::wcout << L"    |-> Size-Y : " << sizeY << std::endl;
    std::wcout << L"    |-> Board  : " << std::endl;

    uintptr_t boardOffset = mineStructAddress + 0x31;
    for (DWORD i = 0; i < sizeY; i++) {
        std::wstring row = L"";
        std::vector<BYTE> rowData(sizeX);
        ReadProcessMemory(hProcess, (LPCVOID)(boardOffset + (i * 32)), rowData.data(), sizeX, NULL);
        for (DWORD j = 0; j < sizeX; j++) {
            if (rowData[j] == 0x0F) {
                row += L" ~ ";
                coValArray.push_back({ static_cast<int>(j), static_cast<int>(i), 0 });
            }
            else {
                row += L" X ";
                coValArray.push_back({ static_cast<int>(j), static_cast<int>(i), 1 });
            }
        }
        std::wcout << row << std::endl;
    }

    HWND hwnd = FindWindow(NULL, _T("Minesweeper"));
    if (hwnd == NULL) {
        std::wcerr << L"Failed to find Minesweeper window" << std::endl;
        return;
    }

    SetForegroundWindow(hwnd);

    RECT rect;
    if (!GetWindowRect(hwnd, &rect)) {
        std::wcerr << L"Failed to get window rectangle" << std::endl;
        return;
    }

    int topLeftX = rect.left + 21;
    int topLeftY = rect.top + 109;

    std::wcout << L"Auto Solver ready..." << std::endl;
    system("pause");
    AutoSolver(hwnd, topLeftX, topLeftY);

    CloseHandle(hProcess);
}

int main() {
    std::wstring windowTitle = L"Minesweeper";
    DWORD processId = GetProcessIdByWindowTitle(windowTitle);

    if (processId == 0) {
        std::wcerr << L"Process not found" << std::endl;
        system("pause");
        return 1;
    }

    ReadWinmineMemory(processId);

    return 0;
}
