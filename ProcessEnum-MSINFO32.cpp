// Process enumeration using msinfo32.exe which can collect everything when generating a report file.
// Instead of dropping to disk the file can be provided over a named pipe back to our calling application.
// I suck at named pipes so the data may be very very dirty. better just save to file its not a virus.
// msinfo32.exe can show processes in the category: software environment > running tasks.

#include <windows.h>
#include <iostream>
#include <string>
#include <thread>

bool runMsInfo32() {
    // Run the systeminfo command
    std::string command = "msinfo32.exe /report \"\\\\.\\pipe\\MsInfo32ProcessEnumertion\"";
    std::cout << "running command: " << command << std::endl;
    FILE* pipe = _popen(command.c_str(), "r");

    if (!pipe) {
        std::cerr << "Error: Unable to run systeminfo command." << std::endl;
        return false;
    }

    // Read the output of the command
    char buffer[1 << 10];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << buffer;
    }

    // Close the pipe and check the exit status
    int exitCode = _pclose(pipe);

    if (exitCode == 0) {
        std::cout << "msinfo run successfully." << std::endl;
    }
    else {
        std::cerr << "Failed to run msinfo" << std::endl;
        return true;
    }

    return true;;
}

bool doPipe() {
    // Define the pipe name
    const wchar_t* pipeName = L"\\\\.\\pipe\\MsInfo32ProcessEnumertion";
    std::wcout << "Creating named pipe: " << pipeName << std::endl;
    // Create the named pipe
    HANDLE hPipe = CreateNamedPipe(
        pipeName,             // Pipe name
        PIPE_ACCESS_INBOUND,  // Read-only access
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,  // Byte-mode pipe
        1,                    // Maximum instances
        0,                    // Out buffer size (unused for read-only)
        0,                    // In buffer size (unused for read-only)
        NMPWAIT_USE_DEFAULT_WAIT,  // Default timeout
        NULL                  // Security attributes
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating named pipe. Error code: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "Waiting for a connection..." << std::endl;

    bool displayData = false; // Flag to control when to display lines
    size_t totalDataRead = 0; // Counter for total data read
    size_t totalDataFiltered = 0; // Counter for total data filtered

    // Wait for a client to connect to the named pipe
    if (ConnectNamedPipe(hPipe, NULL)) {
        std::cout << "Client connected. Reading data..." << std::endl;

        // Read data from the pipe
        DWORD bytesRead;
        WCHAR buffer[1024];
        while (true) {
            if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                std::wstring data(buffer, bytesRead);
                totalDataRead += bytesRead;

                // Check if the line contains [Loaded Modules]
                if (data.find(L"[Loaded Modules]") != std::wstring::npos) {
                    displayData = false; // Stop displaying lines
                }

                // Check if the line contains [Running Tasks]
                if (data.find(L"[Running Tasks]") != std::wstring::npos) {
                    displayData = true; // Start displaying lines
                }

                // Display the line if the flag is true
                if (displayData) {
                    std::wcout << data;
                    totalDataFiltered += bytesRead;
                }

            }
            else {
                // An error occurred or the client disconnected
                DWORD dwError = GetLastError();
                if (dwError == ERROR_BROKEN_PIPE) {
                    std::cout << "Client disconnected. Exiting." << std::endl;
                }
                else {
                    std::cerr << "Error reading from named pipe. Error code: " << dwError << std::endl;
                }
                break; // Exit the loop
            }
        }

        std::cout << "Total data read: " << totalDataRead << " bytes" << std::endl;
        std::cout << "Total data filtered and displayed: " << totalDataFiltered << " bytes" << std::endl;

    }
    else {
        std::cerr << "Error connecting to named pipe. Error code: " << GetLastError() << std::endl;
    }

    // Close the named pipe handle
    CloseHandle(hPipe);

    return true;
}

int main() {
    // Start a separate thread to handle the named pipe
    std::thread pipeThread(doPipe);

    // Run the msinfo32 command in the main thread
    int result = runMsInfo32();

    // Wait for the pipe thread to finish
    pipeThread.join();

    return 0;
}
