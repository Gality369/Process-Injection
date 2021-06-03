// CreateRemoteThreadPro.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
using namespace std;
#include <windows.h>
#include <tchar.h>

HANDLE RtlCreateUserThread(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPVOID lpSpace
)
{
    //The prototype of RtlCreateUserThread from undocumented.ntinternals.com
    typedef DWORD(WINAPI* functypeRtlCreateUserThread)(
        HANDLE      ProcessHandle,
        PSECURITY_DESCRIPTOR  SecurityDescriptor,
        BOOL      CreateSuspended,
        ULONG     StackZeroBits,
        PULONG     StackReserved,
        PULONG     StackCommit,
        LPVOID     StartAddress,
        LPVOID     StartParameter,
        HANDLE      ThreadHandle,
        LPVOID     ClientID
        );

    //Get handle for ntdll which contains RtlCreateUserThread
    HANDLE hRemoteThread = NULL;
    HMODULE hNtDllModule = GetModuleHandle(_T("ntdll.dll"));

    if (hNtDllModule == NULL)
    {
        return NULL;
    }

    functypeRtlCreateUserThread funcRtlCreateUserThread = (functypeRtlCreateUserThread)GetProcAddress(hNtDllModule, "RtlCreateUserThread");

    if (!funcRtlCreateUserThread)
    {
        return NULL;
    }

    funcRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, lpBaseAddress, lpSpace,
        &hRemoteThread, NULL);
    DWORD lastError = GetLastError();
    return hRemoteThread;
}

// NtCreateThreadEx模板
HANDLE NtCreateThreadEx(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPVOID lpSpace
)
{
    //The prototype of NtCreateThreadEx from undocumented.ntinternals.com
    typedef DWORD(WINAPI* functypeNtCreateThreadEx)(
        PHANDLE                 ThreadHandle,
        ACCESS_MASK             DesiredAccess,
        LPVOID                  ObjectAttributes,
        HANDLE                  ProcessHandle,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        LPVOID                  lpParameter,
        BOOL                    CreateSuspended,
        DWORD                   dwStackSize,
        DWORD                   Unknown1,
        DWORD                   Unknown2,
        LPVOID                  Unknown3
        );

    //Get handle for ntdll which contains NtCreateThreadEx
    HANDLE hRemoteThread = NULL;
    HMODULE hNtDllModule = GetModuleHandle(_T("ntdll.dll"));
    if (hNtDllModule == NULL)
    {
        return NULL;
    }

    functypeNtCreateThreadEx funcNtCreateThreadEx = (functypeNtCreateThreadEx)GetProcAddress(hNtDllModule, "NtCreateThreadEx");
    if (!funcNtCreateThreadEx)
    {
        return NULL;
    }
    funcNtCreateThreadEx(&hRemoteThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpBaseAddress, lpSpace, FALSE, NULL, NULL, NULL, NULL);

    return hRemoteThread;
}

int InjectDllByRemoteThreadPro(ULONG32 ulTargetProcessID, WCHAR* wzDllFullPath, int method)
{
    //Gets the process handle for the target process
    HANDLE TargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ulTargetProcessID);
    if (OpenProcess == NULL)
    {
        puts("Could not find process\n");
    }


    //Allocates space inside for inject.dll to our target process
    ULONG32 ulDllLength = (ULONG32)_tcslen(wzDllFullPath) + 1;
    LPVOID lpSpace = (LPVOID)VirtualAllocEx(TargetProcessHandle, NULL, ulDllLength * sizeof(ULONG32), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (lpSpace == NULL)
    {
        printf("Could not allocate memory in process %u\n", ulTargetProcessID);
        return -1;
    }

    //Write dll path to memory of process
    int n = WriteProcessMemory(TargetProcessHandle, lpSpace, (LPVOID)wzDllFullPath, ulDllLength * sizeof(WCHAR), NULL);
    if (n == 0)
    {
        puts("Could not write to process's address space\n");
        return -1;
    }

    HMODULE hModule = GetModuleHandle(_T("kernel32.dll"));
    //Gets address for LoadLibraryA in kernel32.dll
    LPVOID lpBaseAddress = (LPVOID)GetProcAddress(hModule, "LoadLibraryW");

    if (lpBaseAddress == NULL)
    {
        puts("Unable to locate LoadLibraryW\n");
        return -1;
    }



    HANDLE ThreadHandle = INVALID_HANDLE_VALUE;

    switch (method)
    {
    case 1:
        ThreadHandle = NtCreateThreadEx(TargetProcessHandle, lpBaseAddress, lpSpace);
        break;
    case 2:
        ThreadHandle = RtlCreateUserThread(TargetProcessHandle, lpBaseAddress, lpSpace);
        break;
    }

    if (ThreadHandle == NULL)
    {
        return -1;
    }
    else
    {
        DWORD threadId = GetThreadId(ThreadHandle);
        DWORD processId = GetProcessIdOfThread(ThreadHandle);
        printf("Injected thread id: %u for pid: %u", threadId, processId);

        getchar();
        CloseHandle(TargetProcessHandle);
        return 0;
    }
}

int _tmain(int argc, _TCHAR* argv[])
{
    //if (EnableDebugPrivilege() == FALSE) {
    //    return 0;
    //}

    ULONG32 ulProcessID = 0;
    printf("Input the Process ID:");
    cin >> ulProcessID;
    WCHAR wzDllFullPath[MAX_PATH] = { 0 };
    int method = 0;
    printf("Which method?\n 1: NtCreateThread, 2: RtlCreateUserThread :");
    cin >> method;
#ifndef _WIN64
    wcsncat_s(wzDllFullPath, L"D:\\project\\TestDll\\Release\\TestDll.dll", 60);
#else // _WIN64
    wcsncat_s(wzDllFullPath, L"D:\\project\\TestDll\\x64\\Release\\TestDll.dll", 60);
#endif
    int result = InjectDllByRemoteThreadPro(ulProcessID, wzDllFullPath, method);
    if (result == -1)
    {
        puts("Could not inject into PID");
    }
    return 0;
}