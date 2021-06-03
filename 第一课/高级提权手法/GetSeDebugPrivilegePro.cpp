
#include <iostream>
#include <windows.h>
#include <tchar.h>
using namespace std;

BOOL EnableDebugPrivilege() {
    const unsigned long SE_DEBUG_PRIVILEGE = 0x13;
    typedef int(_stdcall* _RtlAdjustPrivilege)(int, BOOL, BOOL, int*);
    HMODULE hNtDll = LoadLibrary(_T("NTDLL.dll")); //导入ntdll
    if (!hNtDll) {
        cout << "Error.." << endl;
        return FALSE;
    }
    _RtlAdjustPrivilege pfnRtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(hNtDll, "RtlAdjustPrivilege");//拿到RtlAdjustPrivilege函数地址

    int nEn = 0;
    pfnRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &nEn); //使用该函数

    return TRUE;
}