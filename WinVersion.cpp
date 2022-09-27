#include <stdio.h>
#include <Windows.h>

int main()
{
    BYTE* sharedUserData = (BYTE*)0x7FFE0000;
    printf("Windows Version: %d.%d.%d\n", *(ULONG*)(sharedUserData + 0x26c), *(ULONG*)(sharedUserData + 0x270), *(ULONG*)(sharedUserData + 0x260));
}
