#include <windows.h>
#include <stdio.h>
#include <winternl.h>

int main()
{
    // get the base address of the current process
    LPVOID imageBase = GetModuleHandleA(NULL);
    printf("Image Base:\t%p\n", imageBase);

    // parse down to IAT
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + ((PIMAGE_DOS_HEADER)imageBase)->e_lfanew);
    printf("Nt Headers:\t%p\n", ntHeaders);
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    printf("Imports Directory:\t%p\n", importsDirectory);
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)imageBase + importsDirectory.VirtualAddress);

    // parse the IAT
    while (importDescriptor->Name) {
        printf("\nImports Descriptor at:\t%p\n", importDescriptor);
        DWORD NameRVA = importDescriptor->Name;
        LPCSTR moduleName = (LPCSTR)((DWORD_PTR)imageBase + NameRVA);
        printf("Module Name:\t%s\n", moduleName);

        // each import descriptor in the table leads another table (thunk) for the exe/dll. original is before loaded and fixed in memory.
        DWORD originFirstThunkRVA = importDescriptor->OriginalFirstThunk;
        PIMAGE_THUNK_DATA originThunkRVA = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + originFirstThunkRVA);
        DWORD thunkRVA = importDescriptor->FirstThunk;
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + thunkRVA);

        // loop through the import tables linked list of "thunks" and get name from origin and address from memory (the not origin)
        while (originThunkRVA->u1.AddressOfData) {
            PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originThunkRVA->u1.AddressOfData);
            printf("\tFunction Name:\t%s\n", import->Name);
            printf("\tFunction Address:\t%p\n", thunk->u1.Function);
            ++thunk;
            ++originThunkRVA;
        }
        ++importDescriptor;
    }
    MessageBoxA(NULL, "Done", "Done", MB_OK);
}