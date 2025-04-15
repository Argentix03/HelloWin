// This is for my home keyboard. I can see the data spiking when i type. just need to decode it somehow. definitely not encrypted just raw and unparsed.
// Found it via WMI (Win32_PnPEntity):
// # Filter for devices with 'Corsair' in the name or instance ID
// Get-PnpDevice | Where-Object{ $_.FriendlyName -like '*Corsair*' -or $_.InstanceId -like '*VID_1B1C*' } | Format-List *
//
// # Specifically look within Keyboard and HID classes
// Get-PnpDevice -Class 'Keyboard' | Where - Object{ $_.FriendlyName -like '*Corsair*' -or $_.InstanceId -like '*VID_1B1C*' } | Format-List *
// Get-PnpDevice -Class 'HIDClass' | Where - Object{ $_.FriendlyName -like '*Corsair*' -or $_.InstanceId -like '*VID_1B1C*' } | Format-List *

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
#include <thread> // For std::thread
#include <mutex>  // For std::mutex and std::lock_guard
#include <atomic> // For graceful shutdown (optional but good)

// Linker directives using pragma comments
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")

// --- Global Variables ---
std::mutex cout_mutex; // Mutex to protect console output
std::atomic<bool> keep_running(true); // Flag to signal threads to stop

// --- Function Prototypes ---
std::wstring FindDevicePath(const std::wstring& targetInstanceId);
void PrintHex(const std::wstring& prefix, const BYTE* buffer, DWORD bytesRead);
void MonitorDevice(const std::wstring targetInstanceId);

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
        std::wcerr << L"Warning: Target device instance ID not found: " << targetInstanceId << std::endl;
    }

    return foundPath;
}

void PrintHex(const std::wstring& prefix, const BYTE* buffer, DWORD bytesRead) {
    std::lock_guard<std::mutex> lock(cout_mutex); // Lock cout for the entire print operation
    std::wcout << L"[" << prefix << L"] Read " << bytesRead << L" bytes: ";
    for (DWORD i = 0; i < bytesRead; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::dec << std::endl; // Reset to decimal output
}

void MonitorDevice(const std::wstring targetInstanceId) {
    std::wstring threadPrefix = L"Mon:" + targetInstanceId.substr(0, 35) + L"..."; // Short prefix for logging

    { // Scope for lock guard message
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcout << L"Thread started for: " << targetInstanceId << std::endl;
    }

    std::wstring devicePath = FindDevicePath(targetInstanceId);
    if (devicePath.empty()) {
        return; // Error message already printed by FindDevicePath
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


    const DWORD bufferSize = 256;
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

    // Add the event handle to an array for potential WaitForMultipleObjects in main
    // (For simple shutdown signal, we use the atomic bool)

    while (keep_running) { // Check the global flag
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
            // Wait for either the read operation OR a short timeout to check keep_running flag
            DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 100); // Wait 100ms

            if (waitResult == WAIT_OBJECT_0) {
                // Operation completed
                if (GetOverlappedResult(hDevice, &overlapped, &bytesRead, FALSE)) {
                    if (bytesRead > 0) {
                        PrintHex(threadPrefix, inputBuffer.data(), bytesRead);
                    }
                }
                else {
                    lastError = GetLastError();
                    if (lastError == ERROR_DEVICE_NOT_CONNECTED || lastError == ERROR_OPERATION_ABORTED || lastError == ERROR_CANCELLED) {
                        std::lock_guard<std::mutex> lock(cout_mutex);
                        std::wcerr << L"[" << threadPrefix << L"] Device disconnected or operation cancelled. GLE=" << lastError << std::endl;
                        break; // Exit loop
                    }
                    else if (keep_running) { // Don't print errors if we are shutting down
                        std::lock_guard<std::mutex> lock(cout_mutex);
                        std::wcerr << L"[" << threadPrefix << L"] Error in GetOverlappedResult. GLE=" << lastError << std::endl;
                        Sleep(100);
                    }
                }
            }
            else if (waitResult == WAIT_TIMEOUT) {
                // Timeout occurred, loop again to check keep_running
                continue;
            }
            else {
                // Wait failed for some other reason
                if (keep_running) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::wcerr << L"[" << threadPrefix << L"] Error: WaitForSingleObject failed. GLE=" << GetLastError() << std::endl;
                }
                break; // Exit loop on wait failure
            }
        }
        else if (readResult) {
            // Completed synchronously
            if (bytesRead > 0) {
                PrintHex(threadPrefix, inputBuffer.data(), bytesRead);
            }
        }
        else {
            // ReadFile failed immediately
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

    // --- Cleanup for this thread ---
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::wcout << L"[" << threadPrefix << L"] Cleaning up thread..." << std::endl;
    }
    CancelIoEx(hDevice, &overlapped);
    CloseHandle(overlapped.hEvent);
    CloseHandle(hDevice);
}

// Console Ctrl Handler to set the keep_running flag
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
        // Handle the CTRL-C signal.
    case CTRL_C_EVENT:
        // Handle CTRL-BREAK signal
    case CTRL_BREAK_EVENT:
        // Handle Console closing
    case CTRL_CLOSE_EVENT:
        // Handle user logoff
    case CTRL_LOGOFF_EVENT:
        // Handle system shutdown
    case CTRL_SHUTDOWN_EVENT:
        std::cout << "\nShutdown signal received. Telling threads to stop..." << std::endl;
        keep_running = false;
        // Give threads a moment to notice the flag before forceful exit
        Sleep(500);
        return TRUE; // Indicate that we handled the event

    default:
        return FALSE;
    }
}


int main() {
    // --- Define Target Device Instance IDs ---
    // Add all the InstanceIDs you want to monitor from your previous list,
    // EXCLUDING the standard keyboard one (USB\Class_03&SubClass_01&Prot_01)
    // and potentially excluding the virtual one initially.
    std::vector<std::wstring> targetInstanceIds = {
        L"HID\\VID_1B1C&PID_1B3D&MI_00&COL04\\8&10335AD1&0&0003", // Vendor UP:FFC2_U:0003
        L"HID\\VID_1B1C&PID_1B3D&MI_01\\8&389E089A&0&0000",       // Vendor UP:FFC2_U:0004
        L"HID\\VID_1B1C&PID_0C10\\7&37BCFC28&0&0000",             // Vendor UP:0084_U:0052 (Different PID)
        L"HID\\VID_1B1C&PID_1B3D&MI_00&COL02\\8&10335AD1&0&0001", // Consumer Control UP:000C_U:0001
        L"HID\\VID_1B1C&PID_1B3D&MI_00&COL03\\8&10335AD1&0&0002", // Vendor UP:FFC0_U:0002     <--- This one seemed really promising on my first test!!
        // Add or remove Instance IDs as needed
        // L"CORSAIRBUS\\VIRTUALDEVICE&10\\1&79F5D87&1&{E7FD4ACE-EE13-11E2-AFDA-000C29100502}" // The virtual one (try if others fail)
    };

    // Set up console control handler for graceful shutdown
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        std::cerr << "Error: Could not set control handler!" << std::endl;
        return 1;
    }
    std::cout << "Monitoring multiple devices. Press Ctrl+C to stop." << std::endl;


    // --- Launch Threads ---
    std::vector<std::thread> monitorThreads;
    for (const auto& instanceId : targetInstanceIds) {
        // Check if path exists before launching thread (optional optimization)
        // std::wstring tempPath = FindDevicePath(instanceId);
        // if (!tempPath.empty()) {
        monitorThreads.emplace_back(MonitorDevice, instanceId);
        // }
    }

    // --- Wait for Threads to Complete ---
    // Threads will run until keep_running is false (due to Ctrl+C) or an error occurs.
    std::cout << "Waiting for threads to complete..." << std::endl;
    for (auto& th : monitorThreads) {
        if (th.joinable()) {
            th.join();
        }
    }

    std::cout << "All monitoring threads have finished." << std::endl;
    return 0;
}