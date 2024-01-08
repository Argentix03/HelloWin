// Process enumeration using WMI. Using COM with the Wbem interface for WMI.
// Executing the query SELECT * FROM Win32_Process to activate the Win32_Process provider.
// Mostly plastered copy paste because COM lol.

#define _WIN32_DCOM
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

struct ProcessInfo {
    wstring name;
    DWORD pid;
};

// Function to compare ProcessInfo objects by PID
bool CompareByPID(const ProcessInfo& a, const ProcessInfo& b) {
    return a.pid < b.pid;
}

int main(int argc, char** argv)
{
    HRESULT hres;
    vector<ProcessInfo> processList;

    // Step 1: Initialize COM.
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cout << "Failed to initialize COM library. Error code = 0x" << hex << hres << endl;
        return 1; // Program has failed.
    }

    // Step 2: Set the COM security levels.
    hres = CoInitializeSecurity(
        nullptr,
        -1,                          // COM authentication
        nullptr,                      // Authentication services
        nullptr,                      // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        nullptr,                      // Authentication info
        EOAC_NONE,                   // Additional capabilities
        nullptr                       // Reserved
    );

    if (FAILED(hres))
    {
        cout << "Failed to initialize security. Error code = 0x" << hex << hres << endl;
        CoUninitialize();
        return 1; // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------
    IWbemLocator* pLoc = nullptr;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<LPVOID*>(&pLoc)
    );

    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object. Error code = 0x" << hex << hres << endl;
        CoUninitialize();
        return 1; // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices* pSvc = nullptr;

    // Connect to the root\cimv2 namespace with the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
        nullptr,                  // User name. NULL = current user
        nullptr,                  // User password. NULL = current user
        0,                        // Locale. NULL indicates current locale
        NULL,                  // Security flags.
        0,                        // Authority (for example, Kerberos)
        0,                        // Context object
        &pSvc                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres))
    {
        cout << "Could not connect. Error code = 0x" << hex << hres << endl;
        pLoc->Release();
        CoUninitialize();
        return 1; // Program has failed.
    }

    cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;

    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        nullptr,                     // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        nullptr,                     // client identity
        EOAC_NONE                    // proxy capabilities
    );

    if (FAILED(hres))
    {
        cout << "Could not set proxy blanket. Error code = 0x" << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1; // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    // For example, get the name of the operating system
    IEnumWbemClassObject* pEnumerator = nullptr;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_Process"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator);

    if (FAILED(hres))
    {
        cout << "Query for operating system name failed. Error code = 0x" << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1; // Program has failed.
    }

    // Step 7: -------------------------------------------------
    // Get the data from the query in step 6 -------------------

    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;

    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;

        // Get the value of the Name property
        hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
        wstring processName = vtProp.bstrVal;
        VariantClear(&vtProp);

        // Get the value of the ProcessId property
        hr = pclsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);
        DWORD processPID = vtProp.uintVal;
        VariantClear(&vtProp);

        // Store process information in the vector
        ProcessInfo processInfo;
        processInfo.name = processName;
        processInfo.pid = processPID;
        processList.push_back(processInfo);

        pclsObj->Release();
    }

    // Sort the list of processes by PID
    sort(processList.begin(), processList.end(), CompareByPID);

    // Print the sorted list of processes
    for (const ProcessInfo& process : processList) {
        wcout << L"PID: " << process.pid << L", Process Name: " << process.name << endl;
    }

    // Cleanup (same as before)

    return 0;

    // Cleanup
    // ========

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    pclsObj->Release();
    CoUninitialize();

    return 0; // Program successfully completed.
}
