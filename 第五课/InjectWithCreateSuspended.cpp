// InjectWithCreateSuspended.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <Windows.h>
#include <iostream>
using namespace std;

BOOL InjectDll(CHAR* ProcessFullPath, CHAR* DllFullPath) {
#ifdef _WIN64
    BYTE code[] = {
    0x48, 0x83, 0xEC, 0x28,             //sub         rsp,28h
    0x48, 0x89, 0x44, 0x24, 0x18,       //mov         qword ptr [rsp+18h],rax           
    0x48, 0x89, 0x4C, 0x24, 0x10,       //mov         qword ptr [rsp+10h],rcx 
    0x48, 0xB9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,  //mov         rcx,1111111111111111h 
    0x48, 0xB8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,  //mov         rax,2222222222222222h
    0xFF, 0xD0,                         //call        rax
    0x48, 0x8B, 0x4C, 0x24, 0x10,       //mov         rcx,qword ptr [rsp+10h]
    0x48, 0x8B, 0x44, 0x24, 0x18,       //mov         rax,qword ptr [rsp+18h]
    0x48, 0x83, 0xC4, 0x28,             //add         rsp,28h
    0x48, 0x83, 0xEC, 0x08,             //sub         rsp,8
    0xC7, 0x04, 0x24, 0x33, 0x33, 0x33, 0x33,  //mov         dword ptr [rsp],33333333h
    0xC7, 0x44, 0x24, 0x04, 0x33, 0x33, 0x33, 0x33, //mov dword ptr [rsp + 4], 33333333h
    0xC3                                //ret
    };
#else
    BYTE code[] = {
    0x60,
    0x68, 0x11, 0x11, 0x11, 0x11,
    0xb8, 0x22, 0x22, 0x22, 0x22,
    0xff, 0xd0,
    0x61,
    0x68, 0x33, 0x33, 0x33, 0x33,
    0xc3
    };
#endif // _WIN64

    CONTEXT ctx;

    //创建挂起线程
    PROCESS_INFORMATION pi;
    STARTUPINFOA Startup;
    ZeroMemory(&Startup, sizeof(Startup));
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(ProcessFullPath, NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &Startup, &pi)) {
        return false;
    }
    printf("创建的进程的ID为：%d\n", pi.dwProcessId);

    //申请空间
    LPVOID RemoteDllPath = VirtualAllocEx(pi.hProcess, NULL, strlen(DllFullPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    printf("DLL路径申请的地址：%p\n", RemoteDllPath);
    LPVOID RemoteCodePath = VirtualAllocEx(pi.hProcess, NULL, sizeof(code) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("Code申请的地址：%p\n", RemoteCodePath);
    //获取上下文
    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(pi.hThread, &ctx);

    //获取LoadLibrary地址
    auto loadLibraryAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
#ifdef _WIN64
    //根据地址，修补我们的代码
    //修补dll的地址，我们把dll地址复制到RemoteDllPath的位置
    * reinterpret_cast<PVOID*>(code + 0x10) = static_cast<void*>(RemoteDllPath);
    //修补LoadLibrary的地址
    *reinterpret_cast<PVOID*>(code + 0x1a) = static_cast<void*>(loadLibraryAddress);
    //修补返回地址，为当前停止的地址的低32位
    *reinterpret_cast<unsigned int*>(code + 0x39) = ctx.Rip & 0xFFFFFFFF;
    //修补返回地址，为当前停止的地址的高32位
    *reinterpret_cast<unsigned int*>(code + 0x41) = ctx.Rip >> 32;
#else
    //根据地址，修补我们的代码
    //修补dll的地址，我们把dll地址复制到RemoteDllPath的位置
    * reinterpret_cast<PVOID*>(code + 2) = static_cast<void*>(RemoteDllPath);
    //修补LoadLibrary的地址
    *reinterpret_cast<PVOID*>(code + 7) = static_cast<void*>(loadLibraryAddress);
    //修补返回地址，为当前停止的地址（eip指向即将执行代码的地址）
    *reinterpret_cast<unsigned*>(code + 0xf) = ctx.Eip;
#endif // _WIN64
    
    //写内存
    if (!WriteProcessMemory(pi.hProcess, RemoteDllPath, DllFullPath, strlen(DllFullPath) + 1, NULL)) {
        VirtualFreeEx(pi.hProcess, RemoteDllPath, strlen(DllFullPath) + 1, MEM_DECOMMIT);
        VirtualFreeEx(pi.hProcess, RemoteCodePath, sizeof(RemoteCodePath) + 1, MEM_DECOMMIT);
        return false;
    }
    if (!WriteProcessMemory(pi.hProcess, RemoteCodePath, code, sizeof(code) + 1, NULL)) {
        VirtualFreeEx(pi.hProcess, RemoteDllPath, strlen(DllFullPath) + 1, MEM_DECOMMIT);
        VirtualFreeEx(pi.hProcess, RemoteCodePath, sizeof(RemoteCodePath) + 1, MEM_DECOMMIT);
        return false;
    }


#ifdef _WIN64
    //设置新的RIP指向Code首地址
    ctx.Rip = reinterpret_cast<unsigned long long>(RemoteCodePath);
#else
    //设置新的EIP指向Code首地址
    ctx.Eip = reinterpret_cast<DWORD>(RemoteCodePath);
#endif // _win64
    //恢复上下文
    ctx.ContextFlags = CONTEXT_CONTROL;
    SetThreadContext(pi.hThread, &ctx);

    //恢复执行程序
    ResumeThread(pi.hThread);

    Sleep(8000);

    VirtualFreeEx(pi.hProcess, RemoteDllPath, strlen(DllFullPath) + 1, MEM_DECOMMIT);
    VirtualFreeEx(pi.hProcess, RemoteCodePath, sizeof(RemoteCodePath) + 1, MEM_DECOMMIT);

    return true;
}


int main()
{
    CHAR ProcessFullPath[MAX_PATH] = { 0 };
    printf("Input the Executable File Full Path:");
    cin >> ProcessFullPath;
    CHAR DllFullPath[MAX_PATH] = { 0 };

#ifndef _WIN64
    strcpy_s(DllFullPath, "D:\\project\\TestDll\\Release\\TestDll.dll");
#else // _WIN64
    strcpy_s(DllFullPath, "D:\\project\\TestDll\\x64\\Release\\TestDll.dll");
#endif

    //注入
    if (!InjectDll(ProcessFullPath, DllFullPath)) {
        printf("Failed to inject DLL");
        return FALSE;
    }
    return 0;
}