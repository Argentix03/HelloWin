// Using fake Registry hive for process enumeration. Performance data is not actually stored in the registry.
// see https://learn.microsoft.com/en-us/windows/win32/perfctrs/using-the-registry-functions-to-consume-counter-data
// and https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexa

// the results for process list parsing (default mode) should kinda be identical to this command (windows built-in tool): typeperf -qx 230 | findstr /c:"ID Process"   or   typeperf "\230(*)\ID Process"

#include <Windows.h>
#include <winperf.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip> // For std::setw, std::setfill, std::hex, std::dec
#include <tuple>   // For storing counter definition info
#include <utility> // For std::pair
#include <algorithm> // For std::sort
#include <map>     // Can be useful, though vector<pair> is fine here
#include <stdexcept> // For error handling if needed


#define INITIAL_BUFFER_SIZE 65536 // 64 KB - Start larger for performance data
#define BUFFER_INCREMENT 32768 // 32 KB

// --- Configuration ---
// Define the Counter Name Title Index for the Object Type representing Processes
const DWORD PROCESS_OBJECT_INDEX = 230; // Set based on user observation
// Define the Counter Name Title Index for Process ID within the Process Object
const DWORD PID_COUNTER_INDEX = 784; // Set based on user observation


// Helper to print raw bytes as hex
void PrintHexBytes(std::wostream& os, const PBYTE data, DWORD size, DWORD maxBytes = 16) {
    os << L"[Hex ";
    for (DWORD i = 0; i < size && i < maxBytes; ++i) {
        os << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(data[i]) << L" ";
    }
    if (size > maxBytes) {
        os << L"...";
    }
    os << L"]" << std::dec; // Switch back to decimal mode
}

// --- Helper Function to find Counter Definition Offset ---
// Searches within an object type for a counter definition by its title index.
// Returns the CounterOffset if found, otherwise returns -1.
// Minimal logging added for clarity during PID search even in default mode.
LONG FindCounterOffset(const PERF_OBJECT_TYPE* pObjectType, DWORD desiredCounterIndex, bool isFullDumpMode) {
    // Bounds check: Ensure HeaderLength is reasonable before calculating start pointer
    if (pObjectType->HeaderLength == 0 || pObjectType->HeaderLength >= pObjectType->DefinitionLength) {
        if (isFullDumpMode) std::wcerr << L"    Warning: Invalid HeaderLength (" << pObjectType->HeaderLength << L") in object type " << pObjectType->ObjectNameTitleIndex << std::endl;
        return -1;
    }

    PERF_COUNTER_DEFINITION* pCounterDef = (PERF_COUNTER_DEFINITION*)((PBYTE)pObjectType + pObjectType->HeaderLength);
    PBYTE pEndOfObjectDefinition = (PBYTE)pObjectType + pObjectType->DefinitionLength;

    for (DWORD k = 0; k < pObjectType->NumCounters; ++k) {
        // Bounds check for reading the current counter definition struct
        if ((PBYTE)pCounterDef + sizeof(PERF_COUNTER_DEFINITION) > pEndOfObjectDefinition) {
            if (isFullDumpMode) std::wcerr << L"    Warning: Counter definition pointer out of bounds reading definition " << k << L" for object " << pObjectType->ObjectNameTitleIndex << std::endl;
            break;
        }
        // Check for zero ByteLength *before* using it to advance
        if (pCounterDef->ByteLength == 0) {
            if (isFullDumpMode) std::wcerr << L"    Warning: Counter Definition [" << k << L"] ByteLength is zero!" << std::endl;
            break; // Avoid infinite loop
        }
        // Bounds check for the *entire* size of the current counter definition struct
        if ((PBYTE)pCounterDef + pCounterDef->ByteLength > pEndOfObjectDefinition) {
            if (isFullDumpMode) std::wcerr << L"    Warning: Counter definition ByteLength " << pCounterDef->ByteLength << L" exceeds object definition boundary for definition " << k << L"." << std::endl;
            break;
        }


        if (pCounterDef->CounterNameTitleIndex == desiredCounterIndex) {
            // Only check size if it's the PID counter we are looking for
            if (desiredCounterIndex == PID_COUNTER_INDEX && pCounterDef->CounterSize != sizeof(DWORD)) {
                if (isFullDumpMode) std::wcerr << L"    Warning: Found PID index " << desiredCounterIndex << L" but size is " << pCounterDef->CounterSize << L" (expected " << sizeof(DWORD) << L")." << std::endl;
                // Continue searching maybe another counter has same index? Unlikely but safer.
            }
            else {
                // Sanity check offset
                if (pCounterDef->CounterOffset != (DWORD)-1 && pCounterDef->CounterOffset <= 20000) { // Max reasonable offset?
                    return static_cast<LONG>(pCounterDef->CounterOffset);
                }
                else {
                    if (isFullDumpMode) std::wcerr << L"    Warning: Found matching index " << desiredCounterIndex << L" but offset " << pCounterDef->CounterOffset << L" seems invalid." << std::endl;
                    return -1;
                }
            }
        }
        // Advance pointer safely
        pCounterDef = (PERF_COUNTER_DEFINITION*)((PBYTE)pCounterDef + pCounterDef->ByteLength);
    }
    return -1; // Indicate counter not found
}


int main(int argc, char* argv[]) { // Add argc/argv for command line args
    bool isFullDumpMode = false;
    // Basic argument check
    if (argc > 1 && (strcmp(argv[1], "--full-dump") == 0 || strcmp(argv[1], "-f") == 0)) {
        isFullDumpMode = true;
        std::wcout << L"--- Full Dump Mode Enabled ---" << std::endl;
    }
    else {
        std::wcout << L"--- Full Dump Mode Disabled (--full-dump) ---" << std::endl;
    }

    DWORD bufferSize = INITIAL_BUFFER_SIZE;
    DWORD cbData = bufferSize;
    LONG result;
    std::vector<BYTE> perfDataBuffer(bufferSize); // Use std::vector

    if (!isFullDumpMode) {
        // std::wcout << L"Retrieving performance data..." << std::endl; // Only show this in default mode (Optional: Remove for cleaner default output)
    }
    else {
        std::wcout << L"Retrieving performance data (full dump)..." << std::endl;
    }

    // --- Buffer Retrieval Loop ---
    while ((result = RegQueryValueExW(HKEY_PERFORMANCE_DATA, // Use W version explicitly
        L"Global",             // Counter path (Global retrieves many things)
        nullptr,               // Reserved
        nullptr,               // Type not needed
        perfDataBuffer.data(), // Pointer to vector's data
        &cbData)) == ERROR_MORE_DATA)
    {
        // Increase buffer size
        bufferSize += BUFFER_INCREMENT;
        // if (!isFullDumpMode) std::wcout << L"."; // Progress dots only in default mode (Optional: Remove)
        std::wcout.flush();
        try {
            perfDataBuffer.resize(bufferSize); // Resize the vector
        }
        catch (const std::bad_alloc& e) {
            std::wcerr << L"\nFailed to allocate memory for buffer: " << e.what() << std::endl;
            return 1;
        }
        cbData = bufferSize; // Reset cbData to the new size for the next call
    }
    // if (!isFullDumpMode) std::wcout << std::endl; // Newline after dots (Optional: Remove)

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"RegQueryValueExW failed with error code: " << result << std::endl;
        return 1;
    }

    if (isFullDumpMode) {
        std::wcout << L"Successfully retrieved data. Final buffer size: " << cbData << L" bytes." << std::endl;
    }

    // --- Data Pointers and Storage ---
    PERF_DATA_BLOCK* pPerfData = reinterpret_cast<PERF_DATA_BLOCK*>(perfDataBuffer.data());
    PBYTE pEndOfBuffer = perfDataBuffer.data() + cbData;
    std::vector<std::pair<std::wstring, DWORD>> processList; // ALWAYS collect potential process data

    // --- Basic Header Validation ---
    if (cbData < sizeof(PERF_DATA_BLOCK) || pPerfData->TotalByteLength != cbData) {
        if (isFullDumpMode) std::wcerr << L"Warning: Data size mismatch." << std::endl;
        // In default mode, we might still proceed if data looks somewhat valid
    }

    // --- Print Header ONLY in Full Dump Mode ---
    if (isFullDumpMode) {
        std::wcout << L"\n--- Performance Data Header ---" << std::endl;
        std::wcout << L"Signature: ";
        for (int k = 0; k < 4; ++k) { if (pPerfData->Signature[k] >= 32 && pPerfData->Signature[k] <= 126) { std::wcout << static_cast<char>(pPerfData->Signature[k]); } else { std::wcout << L'.'; } }
        std::wcout << std::endl;
        std::wcout << L"Version: " << pPerfData->Version << L", Revision: " << pPerfData->Revision << std::endl;
        std::wcout << L"TotalByteLength: " << pPerfData->TotalByteLength << std::endl;
        std::wcout << L"HeaderLength: " << pPerfData->HeaderLength << std::endl;
        std::wcout << L"NumObjectTypes: " << pPerfData->NumObjectTypes << std::endl;
        std::wcout << L"-----------------------------\n" << std::endl;
    }

    // --- Start Parsing Objects ---
    PERF_OBJECT_TYPE* pObjectType = (PERF_OBJECT_TYPE*)((PBYTE)pPerfData + pPerfData->HeaderLength);

    for (DWORD i = 0; i < pPerfData->NumObjectTypes; ++i)
    {
        // *** Bounds Check for Object Type ***
        PBYTE pObjectEnd = (PBYTE)pObjectType + pObjectType->TotalByteLength;
        if ((PBYTE)pObjectType < perfDataBuffer.data() || (PBYTE)pObjectType + sizeof(PERF_OBJECT_TYPE) > pEndOfBuffer || pObjectEnd > pEndOfBuffer || pObjectType->TotalByteLength == 0) {
            if (isFullDumpMode) std::wcerr << L"\nError: Object Type [" << i << L"] pointer or TotalByteLength out of bounds. Stopping." << std::endl;
            break; // Stop parsing if object seems invalid
        }

        // --- Default Mode: Skip objects that are not the target Process Object ---
        if (!isFullDumpMode && pObjectType->ObjectNameTitleIndex != PROCESS_OBJECT_INDEX) {
            // Move to the next object type structure silently
            pObjectType = (PERF_OBJECT_TYPE*)pObjectEnd; // Use calculated end pointer
            continue; // Skip to the next iteration of the loop
        }

        // If we are here, it's either Full Dump Mode OR (Default Mode AND the Process Object)

        // --- Print Object Header ONLY in Full Dump Mode ---
        if (isFullDumpMode) {
            std::wcout << L"\n============================================================" << std::endl;
            std::wcout << L"=== Object Type [" << i << L"] ===" << std::endl;
            std::wcout << L"  ObjectNameTitleIndex: " << pObjectType->ObjectNameTitleIndex << std::endl;
            std::wcout << L"  NumCounters: " << pObjectType->NumCounters << std::endl;
            std::wcout << L"  NumInstances: " << pObjectType->NumInstances << std::endl;
            std::wcout << L"  DefaultCounter: " << pObjectType->DefaultCounter << std::endl;
            std::wcout << L"  DefinitionLength: " << pObjectType->DefinitionLength << std::endl;
            std::wcout << L"  TotalByteLength: " << pObjectType->TotalByteLength << std::endl;
            std::wcout << L"------------------------------------------------------------" << std::endl;
        }

        // --- Store and (Optionally) Print Counter Definitions ---
        std::vector<std::tuple<DWORD, DWORD, DWORD, DWORD>> counterDefs; // Index, Offset, Size, Type
        LONG pidCounterOffsetInThisObject = -1; // Reset for each object we process
        PERF_COUNTER_DEFINITION* pCounterDef = (PERF_COUNTER_DEFINITION*)((PBYTE)pObjectType + pObjectType->HeaderLength);
        PBYTE pEndOfObjectDefinition = (PBYTE)pObjectType + pObjectType->DefinitionLength;

        if (isFullDumpMode) std::wcout << L"  --- Counter Definitions ---" << std::endl;
        for (DWORD k = 0; k < pObjectType->NumCounters; ++k) {
            // Bounds checks
            if ((PBYTE)pCounterDef + sizeof(PERF_COUNTER_DEFINITION) > pEndOfObjectDefinition || (pCounterDef->ByteLength > 0 && (PBYTE)pCounterDef + pCounterDef->ByteLength > pEndOfObjectDefinition)) {
                if (isFullDumpMode) std::wcerr << L"    Error: Counter Definition [" << k << L"] out of bounds." << std::endl; break;
            }
            if (pCounterDef->ByteLength == 0) { if (isFullDumpMode) std::wcerr << L"    Error: Counter Definition [" << k << L"] ByteLength zero." << std::endl; break; }

            // Print ONLY in Full Dump Mode
            if (isFullDumpMode) {
                std::wcout << L"    [" << k << L"] NameIdx: " << std::setw(5) << pCounterDef->CounterNameTitleIndex
                    << L", Offset: " << std::setw(5) << pCounterDef->CounterOffset
                    << L", Size: " << std::setw(2) << pCounterDef->CounterSize
                    << L", Type: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << pCounterDef->CounterType << std::dec << std::setfill(L' ');
            }

            // Check if THIS counter is the PID counter *only if we are processing the Process Object*
            if (pObjectType->ObjectNameTitleIndex == PROCESS_OBJECT_INDEX && // Explicitly check object index
                pCounterDef->CounterNameTitleIndex == PID_COUNTER_INDEX &&
                pCounterDef->CounterSize == sizeof(DWORD))
            {
                // Sanity check offset before storing
                if (pCounterDef->CounterOffset != (DWORD)-1 && pCounterDef->CounterOffset <= 20000) { // Max reasonable offset?
                    pidCounterOffsetInThisObject = static_cast<LONG>(pCounterDef->CounterOffset);
                    if (isFullDumpMode) std::wcout << L" <-- Found PID Counter!";
                }
                else {
                    if (isFullDumpMode) std::wcerr << L" <-- Found PID Index, but Offset invalid: " << pCounterDef->CounterOffset;
                }
            }
            if (isFullDumpMode) std::wcout << std::endl; // Newline after each counter def line in full dump

            // Store definition details REGARDLESS OF MODE (needed if instances exist)
            counterDefs.emplace_back(pCounterDef->CounterNameTitleIndex, pCounterDef->CounterOffset, pCounterDef->CounterSize, pCounterDef->CounterType);
            pCounterDef = (PERF_COUNTER_DEFINITION*)((PBYTE)pCounterDef + pCounterDef->ByteLength); // Advance pointer
        }
        if (isFullDumpMode) std::wcout << L"  ---------------------------" << std::endl;

        // If this is the Process Object but we didn't find the PID offset, something is wrong
        if (pObjectType->ObjectNameTitleIndex == PROCESS_OBJECT_INDEX && pidCounterOffsetInThisObject == -1) {
            if (!isFullDumpMode) std::wcerr << L"Warning: Process Object found, but PID counter (Index " << PID_COUNTER_INDEX << L") definition was not found or invalid." << std::endl;
            // Skip instance processing for this object if PID offset is missing
            pObjectType = (PERF_OBJECT_TYPE*)pObjectEnd; // Move pointer to next object
            continue; // Go to next object type
        }


        // --- Process Instances and their Counter Data ---
        if (pObjectType->NumInstances > 0)
        {
            if (isFullDumpMode) std::wcout << L"\n  --- Instances & Counter Values ---" << std::endl;
            PERF_INSTANCE_DEFINITION* pInstance = (PERF_INSTANCE_DEFINITION*)((PBYTE)pObjectType + pObjectType->DefinitionLength);
            PBYTE pCurrentInstanceStart = (PBYTE)pInstance;

            for (LONG j = 0; j < pObjectType->NumInstances; ++j)
            {
                // *** Instance Bounds Check ***
                PBYTE pExpectedInstanceEnd = pCurrentInstanceStart + pInstance->ByteLength;
                if (pCurrentInstanceStart < (PBYTE)pObjectType + pObjectType->DefinitionLength || pCurrentInstanceStart + sizeof(PERF_INSTANCE_DEFINITION) > pObjectEnd || pInstance->ByteLength == 0 || pExpectedInstanceEnd > pObjectEnd) {
                    if (isFullDumpMode) std::wcerr << L"\n    Error: Instance [" << j << L"] pointer or ByteLength invalid. Stopping instance loop." << std::endl;
                    else if (pObjectType->ObjectNameTitleIndex == PROCESS_OBJECT_INDEX) std::wcerr << L"Warning: Error parsing Instance " << j << L" for Process Object." << std::endl;
                    break;
                }

                // *** Extract Instance Name (with validation) ***
                std::wstring currentInstanceName = L"";
                bool nameIsValid = false;
                PBYTE pNameDataStart = pCurrentInstanceStart + pInstance->NameOffset;
                PBYTE pNameDataEnd = pNameDataStart + pInstance->NameLength;
                if (pInstance->NameOffset >= sizeof(PERF_INSTANCE_DEFINITION) && pInstance->NameLength >= sizeof(wchar_t) && (pInstance->NameLength % sizeof(wchar_t) == 0) && pNameDataStart < pExpectedInstanceEnd && pNameDataEnd <= pExpectedInstanceEnd) {
                    wchar_t* instanceNamePtr = (wchar_t*)pNameDataStart;
                    if (instanceNamePtr[(pInstance->NameLength / sizeof(wchar_t)) - 1] == L'\0') {
                        currentInstanceName = instanceNamePtr;
                        nameIsValid = true;
                    }
                }

                // *** Print Instance Info ONLY in Full Dump Mode ***
                if (isFullDumpMode) {
                    std::wcout << L"\n    Instance [" << j << L"]: \"" << (nameIsValid ? currentInstanceName : L"(Invalid Name)") << L"\"" << std::endl;
                    std::wcout << L"      (Instance Struct @ " << static_cast<void*>(pInstance) << L", Size: " << pInstance->ByteLength << L", NameOff: " << pInstance->NameOffset << L", NameLen: " << pInstance->NameLength << L")" << std::endl;
                }

                // *** Get Counter Block and Check Bounds ***
                PERF_COUNTER_BLOCK* pCounterBlock = (PERF_COUNTER_BLOCK*)pExpectedInstanceEnd;
                PBYTE pCounterBlockStart = (PBYTE)pCounterBlock;
                PBYTE pExpectedCounterBlockEnd = pCounterBlockStart + pCounterBlock->ByteLength;
                DWORD currentInstancePID = (DWORD)-1; // Reset for each instance
                bool pidIsValid = false;

                if (pCounterBlockStart < pExpectedInstanceEnd || pCounterBlockStart + sizeof(PERF_COUNTER_BLOCK) > pObjectEnd || pCounterBlock->ByteLength == 0 || pExpectedCounterBlockEnd > pObjectEnd) {
                    if (isFullDumpMode) std::wcerr << L"      Error: Counter block for instance [" << j << L"] invalid or out of bounds." << std::endl;
                }
                else {
                    if (isFullDumpMode) std::wcout << L"      Counter Block Size: " << pCounterBlock->ByteLength << std::endl;

                    // *** Iterate counters for printing (Full Dump) AND check for PID (Only if Process Object) ***
                    // Only need to iterate if FullDump or if we need the PID
                    if (isFullDumpMode || (pObjectType->ObjectNameTitleIndex == PROCESS_OBJECT_INDEX && pidCounterOffsetInThisObject != -1))
                    {
                        for (const auto& def : counterDefs) {
                            DWORD counterIndex = std::get<0>(def);
                            DWORD counterOffset = std::get<1>(def);
                            DWORD counterSize = std::get<2>(def);
                            PBYTE pCounterData = pCounterBlockStart + counterOffset;

                            // Print counter index ONLY in Full Dump Mode
                            if (isFullDumpMode) std::wcout << L"        Counter Idx: " << std::setw(5) << counterIndex << L": ";

                            // Check bounds for this specific counter
                            if (((PBYTE)pCounterData + counterSize) <= pExpectedCounterBlockEnd) {
                                // Read and print value ONLY in Full Dump Mode
                                if (isFullDumpMode) {
                                    if (counterSize == sizeof(DWORD)) { DWORD value = *(reinterpret_cast<DWORD*>(pCounterData)); std::wcout << L"Val (DWORD) = " << value << L" (0x" << std::hex << value << std::dec << L")"; }
                                    else if (counterSize == sizeof(ULONGLONG)) { ULONGLONG value = *(reinterpret_cast<ULONGLONG*>(pCounterData)); std::wcout << L"Val (ULONGLONG) = " << value << L" (0x" << std::hex << value << std::dec << L")"; }
                                    else { std::wcout << L"Val (Size " << counterSize << L") = "; PrintHexBytes(std::wcout, pCounterData, counterSize); }
                                }

                                // *** Check/Extract PID (Only if Process Object and PID offset known) ***
                                if (pObjectType->ObjectNameTitleIndex == PROCESS_OBJECT_INDEX &&
                                    pidCounterOffsetInThisObject != -1 && // Check if PID offset was found for THIS object
                                    (LONG)counterOffset == pidCounterOffsetInThisObject &&
                                    counterSize == sizeof(DWORD))
                                {
                                    currentInstancePID = *(reinterpret_cast<DWORD*>(pCounterData));
                                    pidIsValid = true;
                                    if (isFullDumpMode) std::wcout << L" <-- PID Found!";
                                    // In default mode, once PID is found, we can stop scanning counters for this instance
                                    if (!isFullDumpMode) break;
                                }
                            }
                            else {
                                if (isFullDumpMode) std::wcout << L"(Counter data out of bounds!)";
                            }
                            if (isFullDumpMode) std::wcout << std::endl;
                        } // end loop through counter defs for this instance
                    } // end if (need to iterate counters)
                } // end else (counter block is valid)

                // *** Store Process/PID Pair IF this IS the Process Object and data is valid ***
                if (pObjectType->ObjectNameTitleIndex == PROCESS_OBJECT_INDEX && nameIsValid && pidIsValid &&
                    currentInstanceName != L"_Total") {
                    processList.push_back({ currentInstanceName, currentInstancePID });
                }

                // Advance instance pointer
                pCurrentInstanceStart = pExpectedCounterBlockEnd;
                pInstance = (PERF_INSTANCE_DEFINITION*)pCurrentInstanceStart;

            } // end loop through instances
            if (isFullDumpMode) std::wcout << L"  --------------------------------" << std::endl;

        }
        // --- Process Global Counters ONLY in Full Dump Mode ---
        else if (isFullDumpMode && pObjectType->NumInstances == PERF_NO_INSTANCES) {
            std::wcout << L"\n  --- Global Counter Values (No Instances) ---" << std::endl;
            // (Global counter printing logic remains the same, wrapped in 'if (isFullDumpMode)')
            PERF_COUNTER_BLOCK* pCounterBlock = (PERF_COUNTER_BLOCK*)((PBYTE)pObjectType + pObjectType->DefinitionLength);
            PBYTE pCounterBlockStart = (PBYTE)pCounterBlock;
            PBYTE pExpectedCounterBlockEnd = pCounterBlockStart + pCounterBlock->ByteLength;
            if (pCounterBlockStart < (PBYTE)pObjectType + pObjectType->DefinitionLength || pCounterBlockStart + sizeof(PERF_COUNTER_BLOCK) > pObjectEnd || pCounterBlock->ByteLength == 0 || pExpectedCounterBlockEnd > pObjectEnd) { std::wcerr << L"      Error: Global counter block invalid or out of bounds." << std::endl; }
            else {
                std::wcout << L"      Counter Block Size: " << pCounterBlock->ByteLength << std::endl;
                for (const auto& def : counterDefs) {
                    DWORD counterIndex = std::get<0>(def);
                    DWORD counterOffset = std::get<1>(def);
                    DWORD counterSize = std::get<2>(def);
                    PBYTE pCounterData = pCounterBlockStart + counterOffset;
                    std::wcout << L"        Counter Idx: " << std::setw(5) << counterIndex << L": ";
                    if (((PBYTE)pCounterData + counterSize) <= pExpectedCounterBlockEnd) {
                        if (counterSize == sizeof(DWORD)) { DWORD value = *(reinterpret_cast<DWORD*>(pCounterData)); std::wcout << L"Val (DWORD) = " << value << L" (0x" << std::hex << value << std::dec << L")"; }
                        else if (counterSize == sizeof(ULONGLONG)) { ULONGLONG value = *(reinterpret_cast<ULONGLONG*>(pCounterData)); std::wcout << L"Val (ULONGLONG) = " << value << L" (0x" << std::hex << value << std::dec << L")"; }
                        else { std::wcout << L"Val (Size " << counterSize << L") = "; PrintHexBytes(std::wcout, pCounterData, counterSize); }
                    }
                    else { std::wcout << L"(Counter data out of bounds!)"; }
                    std::wcout << std::endl;
                }
            }
            std::wcout << L"  ------------------------------------------" << std::endl;
        }
        // ... (Handle other NumInstances values in full dump mode) ...
        else if (isFullDumpMode && pObjectType->NumInstances != 0 && pObjectType->NumInstances != PERF_NO_INSTANCES) { std::wcout << L"\n  (Object has unusual NumInstances value: " << pObjectType->NumInstances << L")" << std::endl; }

        // --- Default Mode: If we just processed the Process Object, we are done ---
        if (!isFullDumpMode && pObjectType->ObjectNameTitleIndex == PROCESS_OBJECT_INDEX) {
            break; // Exit the main object loop
        }


        // Move to the next object type structure
        pObjectType = (PERF_OBJECT_TYPE*)pObjectEnd; // Use calculated end pointer

    } // end loop through object types

    // --- Final Output Section ---

    if (isFullDumpMode) {
        std::wcout << L"\n--- Finished Detailed Parsing ---" << std::endl;
        // DO NOT print the sorted list in full dump mode
    }
    else {
        // Sort the list by PID
        std::sort(processList.begin(), processList.end(),
            [](const std::pair<std::wstring, DWORD>& a, const std::pair<std::wstring, DWORD>& b) {
                return a.second < b.second; // Compare PIDs
            });

        // --- Calculate Max Widths for Formatting ---
        size_t maxPidWidth = 3; // Minimum width for "PID" header
        size_t maxNameWidth = 12; // Minimum width for "Process Name" header
        for (const auto& entry : processList) {
            // Calculate width needed for PID
            std::wstring pidStr = std::to_wstring(entry.second);
            if (pidStr.length() > maxPidWidth) {
                maxPidWidth = pidStr.length();
            }
            // Calculate width needed for Name (including quotes)
            // Add 2 for the quotes ""
            if (entry.first.length() > maxNameWidth) {
                maxNameWidth = entry.first.length() + 2;
            }
        }

        // --- Print Formatted Header ---
        std::wcout << std::right << std::setw(maxPidWidth) << L"PID" << L" | "
            << std::left << std::setw(maxNameWidth) << L"Process Name" << std::endl;
        std::wcout << std::right << std::setfill(L'-') << std::setw(maxPidWidth) << L"" << L"-|-"
            << std::left << std::setfill(L'-') << std::setw(maxNameWidth) << L"" << std::setfill(L' ') << std::endl;


        // --- Print Formatted Data ---
        for (const auto& entry : processList) {
            std::wcout << std::right << std::setw(maxPidWidth) << entry.second << L" | "
                << std::left << std::setw(maxNameWidth) << entry.first << std::endl;
        }
        // Optional: Print total count
        // std::wcout << L"\nTotal Processes Found: " << processList.size() << std::endl;
    }


    return 0;
}
