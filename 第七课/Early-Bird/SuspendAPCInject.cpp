// SuspendAPCInject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include <stdio.h>
#include <iostream>
using namespace std;

BOOL DoInjection(CHAR* ProcessFullPath, CHAR* wzDllFullPath) {
    //申请内存
    WCHAR* lpAddr = NULL;
    SIZE_T page_size = 4096;
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    CreateProcessA(ProcessFullPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    HANDLE victimProcess = pi.hProcess;
    HANDLE threadHandle = pi.hThread;


    lpAddr = (WCHAR*)VirtualAllocEx(victimProcess, nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpAddr) {
        VirtualFreeEx(victimProcess, lpAddr, page_size, MEM_DECOMMIT);
        CloseHandle(victimProcess);
        return FALSE;
    }

    //把Dll的路径复制到内存中
    if (!WriteProcessMemory(victimProcess, lpAddr, wzDllFullPath, (strlen(wzDllFullPath) + 1) * sizeof(wzDllFullPath), nullptr)) {
        VirtualFreeEx(victimProcess, lpAddr, page_size, MEM_DECOMMIT);
        CloseHandle(victimProcess);
        return FALSE;
    }

    //获得LoadLibraryA的地址
    auto loadLibraryAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    //APC注入
    if (!QueueUserAPC((PAPCFUNC)loadLibraryAddress, threadHandle, (ULONG_PTR)lpAddr)) {
        return FALSE;
    }

    ResumeThread(threadHandle);
    return TRUE;
}


int main()
{
    CHAR ProcessFullPath[MAX_PATH] = { 0 };
    printf("Input the Executable File Full Path:");
    cin >> ProcessFullPath;
    CHAR wzDllFullPath[MAX_PATH] = { 0 };


#ifndef _WIN64
    strcpy_s(wzDllFullPath, "D:\\project\\TestDll\\Release\\TestDll.dll");
#else // _WIN64
    strcpy_s(wzDllFullPath, "D:\\project\\TestDll\\x64\\Release\\TestDll.dll");
#endif


    //注入
    if (!DoInjection(ProcessFullPath, wzDllFullPath)) {
        printf("Failed to inject DLL\n");
        return FALSE;
    }
    printf("Success to Inject DLL!\n");
    return 0;
}
