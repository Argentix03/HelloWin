// This is for my home keyboard. I can see the data spiking when i type. just need to decode it somehow. definitely not encrypted just raw and unparsed.
// Found it via WMI (Win32_PnPEntity):
// # Filter for devices with 'Corsair' in the name or instance ID
// Get-PnpDevice | Where-Object{ $_.FriendlyName -like '*Corsair*' -or $_.InstanceId -like '*VID_1B1C*' } | Format-List *
//
// # Specifically look within Keyboard and HID classes
// Get-PnpDevice -Class 'Keyboard' | Where - Object{ $_.FriendlyName -like '*Corsair*' -or $_.InstanceId -like '*VID_1B1C*' } | Format-List *
// Get-PnpDevice -Class 'HIDClass' | Where - Object{ $_.FriendlyName -like '*Corsair*' -or $_.InstanceId -like '*VID_1B1C*' } | Format-List *


// So far analysis:
//Initial State : 03 00 00 00 00 00 00 00 00 ... (All zeros after byte 4)->No keys pressed.
//A Down : 03 00 00 00 00 * *20 * *00 00 00 ...->Byte 5 changed to 20.
//A Up : 03 00 00 00 00 00 00 00 00 ...->Byte 5 returned to 00. System back to idle state.
//B Down : 03 00 00 00 00 00 00 * *40 * *00 ...->Byte 7 changed to 40.
//B Up : 03 00 00 00 00 00 00 00 00 ...->Byte 7 returned to 00. System back to idle state.
//Left Shift Down : 03 00 00 00 00 00 00 * *01 * *00 ...->Byte 8 changed to 01.
//A Down(+Shift) : 03 00 00 00 00 * *20 * *00 * *01 * *00 ...->Byte 5 changed to 20 (like step 2), and Byte 8 remains 01.
//A Up(+Shift) : 03 00 00 00 00 00 00 * *01 * *00 ...->Byte 5 returned to 00, but Byte 8 remains 01 (Shift still held).
//Left Shift Up : 03 00 00 00 00 00 00 00 00 ...->Byte 8 returned to 00. System back to idle state.

// Moving sequentially on the keyboard i can see the different values changing as a bitmask. on for keypress off for no press.
// ignoring (skipping) the bytes reset to 0 on keyup
//'1' Down: 03 00 * *20 * *00 00 ...->Change in Byte 2 (0x20)
//'2' Down : 03 00 * *40 * *00 00 ...->Change in Byte 2 (0x40)
//'3' Down : 03 00 * *80 * *00 00 ...->Change in Byte 2 (0x80)
//'4' Down : 03 00 00 * *01 * *00 ...->Change in Byte 3 (0x01)
//'5' Down : 03 00 00 * *02 * *00 ...->Change in Byte 3 (0x02)
//'6' Down : 03 00 00 * *04 * *00 ...->Change in Byte 3 (0x04)
//'7' Down : 03 00 00 * *08 * *00 ...->Change in Byte 3 (0x08)
//'8' Down: 03 00 00 * *10 * *00 ...->Change in Byte 3 (0x10)
//'9' Down : 03 00 00 * *20 * *00 ...->Change in Byte 3 (0x20)
//'0' Down : 03 00 00 * *40 * *00 ...->Change in Byte 3 (0x40)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <hidpi.h>
#include <cfgmgr32.h> // For CM_Get_Device_ID
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <thread> // Still useful for non-blocking main thread
#include <mutex>
#include <atomic>
#include <cwchar>   // For wcscmp, wcstol
#include <map>      
#include <utility>  // (for std::pair implicitly used by map key)
#include <sstream>  // (for formatting output)

// Linker directives using pragma comments
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")

// --- Global Variables ---
std::mutex cout_mutex;
std::atomic<bool> keep_running(true);

struct BitPosition {
    int byteIndex;
    int bitIndex; // 0-7

    bool operator<(const BitPosition& other) const {
        if (byteIndex != other.byteIndex) return byteIndex < other.byteIndex;
        return bitIndex < other.bitIndex;
    }
};

std::map<BitPosition, std::string> keyMap; // Global Key Map

// --- Function Prototypes ---
std::wstring FindDevicePath(const std::wstring& targetInstanceId);
void PrintHex(const std::wstring& prefix, const BYTE* buffer, DWORD bytesRead, DWORD filterSize);
void PopulateKeyMap(); // Added
void ParseAndPrintKeys(const std::wstring& prefix, const BYTE* buffer, DWORD bytesRead); // Added
void MonitorDevice(const std::wstring targetInstanceId, DWORD filterSize, bool parseKeys); // Modified signature
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType);
void PrintUsage(wchar_t* programName);

// --- Function Definitions ---

std::wstring FindDevicePath(const std::wstring& targetInstanceId) {
    GUID hidGuid;
    HidD_GetHidGuid(&hidGuid);

    HDEVINFO hDevInfo = SetupDiGetClassDevs(&hidGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcerr << L"Error: SetupDiGetClassDevs failed for [" << targetInstanceId << L"]. GLE=" << GetLastError() << std::endl;
        return L"";
    }

    SP_DEVICE_INTERFACE_DATA devInterfaceData;
    devInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    DWORD deviceIndex = 0;
    std::wstring foundPath = L"";

    while (SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &hidGuid, deviceIndex, &devInterfaceData)) {
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetail(hDevInfo, &devInterfaceData, NULL, 0, &requiredSize, NULL);

        if (requiredSize > 0) {
            std::vector<BYTE> detailDataBuffer(requiredSize);
            PSP_DEVICE_INTERFACE_DETAIL_DATA detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)detailDataBuffer.data();
            detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
            SP_DEVINFO_DATA devInfoData;
            devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

            if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &devInterfaceData, detailData, requiredSize, NULL, &devInfoData)) {
                WCHAR instanceIdBuffer[512];
                CONFIGRET cr = CM_Get_Device_ID(devInfoData.DevInst, instanceIdBuffer, sizeof(instanceIdBuffer) / sizeof(instanceIdBuffer[0]), 0);
                if (cr == CR_SUCCESS) {
                    std::wstring currentInstanceId = instanceIdBuffer;
                    // Case-insensitive comparison
                    if (_wcsicmp(currentInstanceId.c_str(), targetInstanceId.c_str()) == 0) {
                        foundPath = detailData->DevicePath;
                        break;
                    }
                }
            }
        }
        deviceIndex++;
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);

    if (foundPath.empty()) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcerr << L"Error: Target device instance ID not found: " << targetInstanceId << std::endl;
    }

    return foundPath;
}

// Modified PrintHex to include size filter logic
void PrintHex(const std::wstring& prefix, const BYTE* buffer, DWORD bytesRead, DWORD filterSize) {
    // Apply filter: Print only if filterSize is 0 (disabled) or matches bytesRead
    if (filterSize == 0 || bytesRead == filterSize) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcout << L"[" << prefix << L"] Read " << bytesRead << L" bytes: ";
        for (DWORD i = 0; i < bytesRead; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";
        }
        std::cout << std::dec << std::endl;
    }
}

void PopulateKeyMap() {
    std::lock_guard<std::mutex> lock(cout_mutex); // Protect map access if called concurrently (though not in this design)
    std::cout << "Populating key map..." << std::endl;
    keyMap.clear(); // Ensure it's empty before populating

    // --- Populate based on previous findings ---

    // Byte 2
    keyMap[{2, 5}] = "1";
    keyMap[{2, 6}] = "2";
    keyMap[{2, 7}] = "3";
    // Byte 3
    keyMap[{3, 0}] = "4";
    keyMap[{3, 1}] = "5";
    keyMap[{3, 2}] = "6";
    keyMap[{3, 3}] = "7";
    keyMap[{3, 4}] = "8";
    keyMap[{3, 5}] = "9";
    keyMap[{3, 6}] = "0";
    // Byte 4 - ADD MAPPINGS HERE FOR QWERTY ROW (e.g., Q, W, E, R...)
    // keyMap[{4, 0}] = "Q"; // Example - determine the actual bit
    // keyMap[{4, 1}] = "W"; // Example
    // ...
    // Byte 5
    keyMap[{5, 5}] = "A"; // From A/B test
    // Add S, D, F, G, H, J, K, L here
    // ...
    // Byte 6 - ADD MAPPINGS HERE FOR ZXCV ROW
    // ...
    // Byte 7
    keyMap[{7, 6}] = "B"; // From A/B test
    // Add N, M, Comma, Period, Slash here
    // ...

    // Byte 8 - Modifiers (and potentially other keys like Space?)
    keyMap[{8, 0}] = "LShift";
    // keyMap[{8, 1}] = "LCtrl";  // Determine bit index by testing
    // keyMap[{8, 2}] = "LAlt";   // Determine bit index by testing
    // keyMap[{8, 3}] = "LGui";   // (Win Key) Determine bit index by testing
    // keyMap[{8, 4}] = "RShift"; // Determine bit index by testing
    // keyMap[{8, 5}] = "RCtrl";  // Determine bit index by testing
    // keyMap[{8, 6}] = "RAlt";   // Determine bit index by testing
    // keyMap[{8, 7}] = "RGui";   // Determine bit index by testing

    // ADD MAPPINGS FOR Space, Enter, Backspace by testing them individually
    // Example: Press Space, see which bit changes -> keyMap[{byte, bit}] = "Space";
    // Example: Press Enter, see which bit changes -> keyMap[{byte, bit}] = "Enter";
    // Example: Press Backspace, see which bit changes -> keyMap[{byte, bit}] = "Backspace";

    std::cout << "Key map populated with " << keyMap.size() << " known keys." << std::endl;
    std::cout << "NOTE: Map is incomplete. Please test and add missing keys." << std::endl;
}

// Parses Report ID 0x03 and prints pressed keys
void ParseAndPrintKeys(const std::wstring& prefix, const BYTE* buffer, DWORD bytesRead) {
    if (bytesRead < 9) return; // Need at least up to byte 8 for basic modifiers/keys

    std::vector<std::string> pressedKeys;
    std::vector<std::string> pressedModifiers;

    // Iterate through the potential bitmap bytes
    // Adjust the upper limit (e.g., 16) if keys map to higher bytes
    const int maxByteIndexToCheck = 16;
    for (int byteIdx = 2; byteIdx < bytesRead && byteIdx < maxByteIndexToCheck; ++byteIdx) {
        BYTE currentByte = buffer[byteIdx];
        if (currentByte == 0) continue; // Skip if no bits are set in this byte

        for (int bitIdx = 0; bitIdx < 8; ++bitIdx) {
            // Check if the current bit is set
            if ((currentByte >> bitIdx) & 1) {
                BitPosition pos = { byteIdx, bitIdx };
                auto it = keyMap.find(pos);
                if (it != keyMap.end()) {
                    // Separate modifiers (assuming they are mostly in byte 8)
                    if (byteIdx == 8) {
                        pressedModifiers.push_back(it->second);
                    }
                    else {
                        pressedKeys.push_back(it->second);
                    }
                }
                else {
                    // Optional: Report unknown bits that are set
                    // std::lock_guard<std::mutex> lock(cout_mutex);
                    // std::wcerr << L"[" << prefix << L"] Unknown bit set at Byte " << byteIdx << ", Bit " << bitIdx << std::endl;
                }
            }
        }
    }

    // --- Print the result ---
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::wcout << L"[" << prefix << L"] Parsed Keys: ";
    if (pressedModifiers.empty() && pressedKeys.empty()) {
        std::wcout << L"(None)" << std::endl;
    }
    else {
        // Print Modifiers first
        for (size_t i = 0; i < pressedModifiers.size(); ++i) {
            std::cout << pressedModifiers[i] << ((i < pressedModifiers.size() - 1 || !pressedKeys.empty()) ? "+" : "");
        }
        // Print Keys
        for (size_t i = 0; i < pressedKeys.size(); ++i) {
            std::cout << pressedKeys[i] << (i < pressedKeys.size() - 1 ? " " : "");
        }
        std::cout << std::endl;
    }
}

void MonitorDevice(const std::wstring targetInstanceId, DWORD filterSize, bool parseKeys) {
    std::wstring threadPrefix = L"Mon:" + targetInstanceId.substr(0, 35) + L"...";

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcout << L"Attempting to monitor: " << targetInstanceId << std::endl;
        if (parseKeys) {
            std::wcout << L"Key parsing enabled for Report ID 0x03." << std::endl;
        }
        if (filterSize > 0) {
            std::wcout << L"Filtering for report size: " << filterSize << L" bytes." << std::endl;
        }
        else {
            std::wcout << L"No report size filter applied." << std::endl;
        }
    }

    std::wstring devicePath = FindDevicePath(targetInstanceId);
    if (devicePath.empty()) {
        return;
    }

    HANDLE hDevice = CreateFile(
        devicePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcerr << L"[" << threadPrefix << L"] Error: Failed to open device handle. GLE=" << GetLastError() << std::endl;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcout << L"[" << threadPrefix << L"] Device opened successfully. Listening..." << std::endl;
    }


    const DWORD bufferSize = 1024; // Increased buffer size just in case
    std::vector<BYTE> inputBuffer(bufferSize);
    DWORD bytesRead = 0;
    OVERLAPPED overlapped;
    ZeroMemory(&overlapped, sizeof(overlapped));
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (overlapped.hEvent == NULL) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcerr << L"[" << threadPrefix << L"] Error: Failed to create event. GLE=" << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return;
    }

    while (keep_running) {
        ResetEvent(overlapped.hEvent);
        BOOL readResult = ReadFile(
            hDevice,
            inputBuffer.data(),
            bufferSize,
            &bytesRead,
            &overlapped
        );

        DWORD lastError = GetLastError();

        if (!readResult && lastError == ERROR_IO_PENDING) {
            DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 100); // Wait 100ms

            if (waitResult == WAIT_OBJECT_0) {
                if (GetOverlappedResult(hDevice, &overlapped, &bytesRead, FALSE)) {
                    if (bytesRead > 0) {
                        // --- PARSING LOGIC ---
                        if (parseKeys && inputBuffer[0] == 0x03) { // Check flag and Report ID
                            ParseAndPrintKeys(threadPrefix, inputBuffer.data(), bytesRead);
                            // For now just print hex anyways.
                            PrintHex(threadPrefix, inputBuffer.data(), bytesRead, filterSize);
                        }
                        else if (!parseKeys) { // Only print hex if parsing is disabled
                            PrintHex(threadPrefix, inputBuffer.data(), bytesRead, filterSize);
                        } // Else (parseKeys is true but wrong report ID): Do nothing for now
                    }
                }
                else {
                    lastError = GetLastError();
                    if (lastError == ERROR_DEVICE_NOT_CONNECTED || lastError == ERROR_OPERATION_ABORTED || lastError == ERROR_CANCELLED) {
                        std::lock_guard<std::mutex> lock(cout_mutex);
                        std::wcerr << L"[" << threadPrefix << L"] Device disconnected or operation cancelled. GLE=" << lastError << std::endl;
                        break;
                    }
                    else if (keep_running) {
                        std::lock_guard<std::mutex> lock(cout_mutex);
                        std::wcerr << L"[" << threadPrefix << L"] Error in GetOverlappedResult. GLE=" << lastError << std::endl;
                        Sleep(100);
                    }
                }
            }
            else if (waitResult == WAIT_TIMEOUT) {
                continue;
            }
            else {
                if (keep_running) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::wcerr << L"[" << threadPrefix << L"] Error: WaitForSingleObject failed. GLE=" << GetLastError() << std::endl;
                }
                break;
            }
        }
        else if (readResult) { // Completed synchronously
            if (bytesRead > 0) {
                if (parseKeys && inputBuffer[0] == 0x03) { // Check flag and Report ID
                    ParseAndPrintKeys(threadPrefix, inputBuffer.data(), bytesRead);
                    // For now just print hex anyways.
                    PrintHex(threadPrefix, inputBuffer.data(), bytesRead, filterSize);
                }
                else if (!parseKeys) { // Only print hex if parsing is disabled
                    PrintHex(threadPrefix, inputBuffer.data(), bytesRead, filterSize);
                } // Else (parseKeys is true but wrong report ID): Do nothing for now
            }
        }
        else {
            if (lastError == ERROR_DEVICE_NOT_CONNECTED || lastError == ERROR_OPERATION_ABORTED || lastError == ERROR_CANCELLED) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::wcerr << L"[" << threadPrefix << L"] Device disconnected or op cancelled (Immediate Fail). GLE=" << lastError << std::endl;
                break;
            }
            else if (keep_running) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::wcerr << L"[" << threadPrefix << L"] Error: ReadFile failed immediately. GLE=" << lastError << std::endl;
                break;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcout << L"[" << threadPrefix << L"] Cleaning up monitoring thread..." << std::endl;
    }
    CancelIoEx(hDevice, &overlapped);
    CloseHandle(overlapped.hEvent);
    CloseHandle(hDevice);
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (keep_running) { // Prevent multiple prints if handler called rapidly
            std::cout << "\nShutdown signal received. Telling monitor thread to stop..." << std::endl;
            keep_running = false;
        }
        // Give thread a moment to notice the flag before forceful exit might occur
        Sleep(500);
        return TRUE;
    default:
        return FALSE;
    }
}

void PrintUsage(wchar_t* programName) {
    std::wcerr << L"Usage: " << programName << " --device \"<Device Instance ID>\" [--size <report_size>]" << std::endl;
    std::wcerr << L"Example:" << std::endl;
    std::wcerr << L"  " << programName << " --device \"HID\\VID_1B1C&PID_1B3D&MI_00&COL03\\8&10335AD1&0&0002\"" << std::endl;
    std::wcerr << L"  " << programName << " --device \"HID\\VID_1B1C&PID_1B3D&MI_00&COL03\\8&10335AD1&0&0002\" --size 64" << std::endl;
    std::wcerr << std::endl;
    std::wcerr << L"  Use quotes around the Device Instance ID." << std::endl;
    std::wcerr << L"  --size is optional. If provided, only reports matching that size will be printed." << std::endl;
    std::wcerr << L"  -p, --parse-keys    Optional. Attempt to parse Report ID 0x03 as key presses." << std::endl;
}


// Use wmain for wide character arguments
int wmain(int argc, wchar_t* argv[]) {
    std::wstring targetInstanceId = L"";
    DWORD filterSize = 0;       // flag --size
    bool parseKeysFlag = false; // flag --parse-keys

    // --- Argument Parsing ---
    for (int i = 1; i < argc; ++i) {
        if ((_wcsicmp(argv[i], L"--device") == 0 || _wcsicmp(argv[i], L"-d") == 0) && (i + 1 < argc)) {
            targetInstanceId = argv[i + 1];
            i++; // Skip the value argument
        }
        else if ((_wcsicmp(argv[i], L"--size") == 0 || _wcsicmp(argv[i], L"-s") == 0) && (i + 1 < argc)) {
            wchar_t* endPtr;
            long sizeVal = wcstol(argv[i + 1], &endPtr, 10); // Use wcstol for robust conversion
            // Check if conversion was successful and value is non-negative
            if (*endPtr == L'\0' && sizeVal >= 0) {
                filterSize = static_cast<DWORD>(sizeVal);
            }
            else {
                std::wcerr << L"Error: Invalid value for --size argument: " << argv[i + 1] << std::endl;
                PrintUsage(argv[0]);
                return 1;
            }
            i++; // Skip the value argument
        }
        else if (_wcsicmp(argv[i], L"--parse-keys") == 0 || _wcsicmp(argv[i], L"-p") == 0) {
            parseKeysFlag = true;
        }
        else {
            std::wcerr << L"Error: Unknown or invalid argument: " << argv[i] << std::endl;
            PrintUsage(argv[0]);
            return 1;
        }
    }

    // --- Validate Arguments ---
    if (targetInstanceId.empty()) {
        std::wcerr << L"Error: --device argument is required." << std::endl;
        PrintUsage(argv[0]);
        return 1;
    }

    // --- Populate Key Map ---
    // Do this BEFORE starting the thread that needs it
    if (parseKeysFlag) { // Only populate if needed
        PopulateKeyMap();
    }


    // Set up console control handler for graceful shutdown
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        std::cerr << "Error: Could not set control handler!" << std::endl;
        return 1;
    }
    std::wcout << L"Starting monitor. Press Ctrl+C to stop." << std::endl;

    // --- Launch Monitor Thread ---
    // We run the monitor in a separate thread so main can wait for Ctrl+C
    // without blocking indefinitely if the monitor thread exits early due to error.
    std::thread monitorThread(MonitorDevice, targetInstanceId, filterSize, parseKeysFlag);

    // --- Wait for Shutdown Signal ---
    while (keep_running) {
        Sleep(200); // Sleep main thread while worker runs
    }

    // --- Wait for Monitor Thread to Complete ---
    std::cout << "Waiting for monitor thread to clean up..." << std::endl;
    if (monitorThread.joinable()) {
        monitorThread.join();
    }

    std::cout << "Monitoring thread finished." << std::endl;
    return 0;
}