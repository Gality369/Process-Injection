// LocalAPCInject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)();

int main()
{
	CHAR DllFullPath[MAX_PATH] = { 0 };

	#ifndef _WIN64
		strcpy_s(DllFullPath, "D:\\project\\TestDll\\Release\\TestDll.dll");
	#else // _WIN64
		strcpy_s(DllFullPath, "D:\\project\\TestDll\\x64\\Release\\TestDll.dll");
	#endif

	myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
	LPVOID lpAddr = VirtualAlloc(NULL, sizeof(DllFullPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(GetCurrentProcess(), lpAddr, DllFullPath, sizeof(DllFullPath), NULL);


	//获得LoadLibraryA的地址
	auto loadLibraryAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	//APC注入
	if (!QueueUserAPC((PAPCFUNC)loadLibraryAddress, GetCurrentThread(), (ULONG_PTR)lpAddr)) {
		printf("Inject APC Queue");
	}
	testAlert();

	return 0;
}