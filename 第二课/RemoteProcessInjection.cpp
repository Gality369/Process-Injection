// RemoteProcessInjection.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <tchar.h>
using namespace std;
BOOL EnableDebugPrivilege();
BOOL InjectDllByRemoteThread(ULONG32 ulTargetProcessID, WCHAR* wzDllFullPath);

int _tmain(int argc, _TCHAR* argv[])
{
    if (EnableDebugPrivilege() == FALSE) {
        printf("failed to get SeDebug Privilege");
        return -1;
    }
    ULONG32 ulProcessID = 0;
    printf("Input the Process ID:");
    cin >> ulProcessID;
    WCHAR wzDllFullPath[MAX_PATH] = { 0 };
#ifndef _WIN64
    wcsncat_s(wzDllFullPath, L"D:\\project\\TestDll\\Release\\TestDll.dll", 60);
#else // _WIN64
    wcsncat_s(wzDllFullPath, L"D:\\project\\TestDll\\x64\\Release\\TestDll.dll", 60);
#endif
    InjectDllByRemoteThread(ulProcessID, wzDllFullPath);
    return 0;
}


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


BOOL InjectDllByRemoteThread(ULONG32 ulTargetProcessID, WCHAR* wzDllFullPath) {
    HANDLE TargetProcessHandle = NULL;
    TargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ulTargetProcessID);
    //open handle
    if (TargetProcessHandle == NULL) {
        printf("failed to open Process");
        return FALSE;
    }

    //get address of remote process
    WCHAR* VirtualAddress = NULL;
    ULONG32 ulDllLength = (ULONG32)_tcslen(wzDllFullPath) + 1;
    VirtualAddress = (WCHAR*)VirtualAllocEx(TargetProcessHandle, NULL, ulDllLength * sizeof(ULONG32), MEM_COMMIT, PAGE_READWRITE);
    if (VirtualAddress == NULL) {
        printf("failed to Alloc!");
        CloseHandle(TargetProcessHandle);
        return FALSE;
    }

    //write 
    if (FALSE == WriteProcessMemory(TargetProcessHandle, VirtualAddress, (LPVOID)wzDllFullPath, ulDllLength * sizeof(WCHAR), NULL)) {
        printf("failed to write\n");
        VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT | MEM_RELEASE);
        CloseHandle(TargetProcessHandle);
        return FALSE;
    }
    LPTHREAD_START_ROUTINE FunctionAddress = NULL;
    FunctionAddress = (LPTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("kernel32")), "LoadLibraryW");
    HANDLE ThreadHandle = INVALID_HANDLE_VALUE;

    //start
    ThreadHandle = CreateRemoteThread(TargetProcessHandle, NULL, 0, FunctionAddress, VirtualAddress, 0, NULL);
    if (ThreadHandle == NULL) {
        VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT | MEM_RELEASE);
        CloseHandle(TargetProcessHandle);
        return FALSE;
    }

    //wait for single object
    WaitForSingleObject(ThreadHandle, INFINITE);
    VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT | MEM_RELEASE);
    CloseHandle(ThreadHandle);
    CloseHandle(TargetProcessHandle);
    return TRUE;
    
}