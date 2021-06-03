// APCInjectRing3.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
using namespace std;

//列出指定进程的所有线程
BOOL GetProcessThreadList(DWORD th32ProcessID, DWORD** ppThreadIdList, LPDWORD pThreadIdListLength) {
    DWORD dwThreadIdListLength = 0;
    DWORD dwThreadIdListMaxCount = 2000;
    LPDWORD pThreadIdList = NULL;
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    pThreadIdList = (LPDWORD)VirtualAlloc(NULL, dwThreadIdListMaxCount * sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pThreadIdList == NULL) {
        return FALSE;
    }
    RtlZeroMemory(pThreadIdList, dwThreadIdListMaxCount * sizeof(DWORD));
    THREADENTRY32 th32 = { 0 };
    //对指定进程拍摄快照
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, th32ProcessID);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return(FALSE);
    //使用前先填写结构的大小
    th32.dwSize = sizeof(THREADENTRY32);
    //遍历所有THREADENTRY32结构, 按顺序填入数组
    BOOL bRet = Thread32First(hThreadSnap, &th32);
    while (bRet) {
        if (th32.th32OwnerProcessID == th32ProcessID) {
            if (dwThreadIdListLength >= dwThreadIdListMaxCount) {
                break;
            }
            pThreadIdList[dwThreadIdListLength++] = th32.th32ThreadID;
        }
        bRet = Thread32Next(hThreadSnap, &th32);
    }
    *pThreadIdListLength = dwThreadIdListLength;
    *ppThreadIdList = pThreadIdList;
    return TRUE;
}


BOOL DoInjection(HANDLE hProcess, CHAR* wzDllFullPath, LPDWORD pThreadIdList, DWORD dwThreadIdListLength) {
    //申请内存
    WCHAR* lpAddr = NULL;
    SIZE_T page_size = 4096;
    lpAddr = (WCHAR*)VirtualAllocEx(hProcess, nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpAddr) {
        VirtualFreeEx(hProcess, lpAddr, page_size, MEM_DECOMMIT);
        CloseHandle(hProcess);
        return FALSE;
    }

    //把Dll的路径复制到内存中
    if (!WriteProcessMemory(hProcess, lpAddr, wzDllFullPath, (strlen(wzDllFullPath) + 1) * sizeof(wzDllFullPath), nullptr)) {
        VirtualFreeEx(hProcess, lpAddr, page_size, MEM_DECOMMIT);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    //获得LoadLibraryA的地址
    auto loadLibraryAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    //遍历APC
    float fail = 0;
    for (int i = dwThreadIdListLength - 1; i >= 0; i--) {
        HANDLE hThread  = OpenThread(THREAD_ALL_ACCESS, FALSE, pThreadIdList[i]);
        if (hThread) {
            if (!QueueUserAPC((PAPCFUNC)loadLibraryAddress, hThread, (ULONG_PTR)lpAddr)) {
                fail++;
            }
            CloseHandle(hThread);
            hThread = NULL;
        }
    }
    printf("Total Thread: %d\n", dwThreadIdListLength);
    printf("Total Failed: %d\n", (int)fail);
    if ((int)fail == 0 || dwThreadIdListLength / fail > 0.5) {
        printf("Success to Inject APC\n");
        return TRUE;
    }
    else {
        printf("Inject may be failed\n");
        return FALSE;
    } 
}

int main()
{
    ULONG32 ulProcessID = 0;
    printf("Input the Process ID:");
    cin >> ulProcessID;
    CHAR wzDllFullPath[MAX_PATH] = { 0 };
    LPDWORD pThreadIdList = NULL;
    DWORD dwThreadIdListLength = 0;

#ifndef _WIN64
    strcpy_s(wzDllFullPath, "D:\\project\\TestDll\\Release\\TestDll.dll");
#else // _WIN64
    strcpy_s(wzDllFullPath, "D:\\project\\TestDll\\x64\\Release\\TestDll.dll");
#endif

    if (!GetProcessThreadList(ulProcessID, &pThreadIdList, &dwThreadIdListLength)) {
        printf("Can not list the threads!\n");
        exit(0);
    }

    //打开句柄资源
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, ulProcessID);
    if (hProcess == NULL) {
        printf("failed to open Process\n");
        return FALSE;
    }

    //注入
    if (!DoInjection(hProcess, wzDllFullPath, pThreadIdList, dwThreadIdListLength)) {
        printf("Failed to inject DLL\n");
        return FALSE;
    }
    return 0;
}

