Title: Ghost dll injections
Date: 2019-3-30 10:01
Modified: 2019-3-30 10:01
Category: tutorial
Tags: windows, binary exploitation
Slug: ghost_dll_injection
Authors: F3real
Summary: Example of simple dll injection

[TOC]

Dynamic Link Library (`dll`) are compiled shared function libraries that can be dynamically loaded by Windows programs. Linux uses Shared Object (`so`) files for the same purpose.

##dll search order

Order of locations in which dll is searched for depends if `SafeDllSearchMode` is set to true (default) or not.

To disable `SafeDllSearchMode` we can create following registry key and set its value to 0:

~~~text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode
~~~

If `SafeDllSearchMode` is enabled, the search order for desktop applications is as follows:

1. The directory from which the application loaded.
2. The system directory. Use the `GetSystemDirectory` function to get the path of this directory.
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched.
4. The Windows directory. Use the GetWindowsDirectory function to get the path of this directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the App Paths registry key. The App Paths key is not used when computing the DLL search path.

If `SafeDllSearchMode` is disabled, the search order is as follows:

1. The directory from which the application loaded.
2. The current directory.
3. The system directory. Use the `GetSystemDirectory` function to get the path of this directory.
4. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched.
5. The Windows directory. Use the GetWindowsDirectory function to get the path of this directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the App Paths registry key. The App Paths key is not used when computing the DLL search path.

Before the system searches for a DLL, it checks the following:

1. If a DLL with the same module name is already loaded in memory, the system uses the loaded DLL, no matter which directory it is in. The system does not search for the DLL.
2. If the DLL is on the list of known DLLs for the version of Windows on which the application is running, the system uses its copy of the known DLL (and the known DLL's dependent DLLs, if any). The system does not search for the DLL. For a list of known DLLs on the current system, see the following registry key: 
    
~~~text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
~~~

Dll search order can also be changed programmatically. More information on dll load order can be found [here](https://docs.microsoft.com/en-us/windows/desktop/dlls/dynamic-link-library-search-order).

##dll injection

Dll injection happens if we can insert our own dll in location with higher search priority then real dll or replace it. If we want to be stealthy, with this approach, we also need to export all functions that real dll provides (by loading it as dependency and re-exporting its functions).

Sometimes applications try to load dlls that don't exist on system. In this case, we don't have to worry about original functionality of dll. Usually this type of dll injection is called ghost dll injection.

##Finding missing dlls

One of the ways to find dlls that application try to load is to use `Procmon`.
We need to set following filters:

~~~text
Process Name    is           <target.exe>       Include
Operation       is           CreateFile         Include
Path            ends with    .dll               Include
Result          is not       SUCCESS            Include
~~~

For example lets try it on hl.exe:

![Procmon results on hl.exe]({static}/images/2019_3_30_dll.png){: .img-fluid .centerimage}

We see that `p2pvoice.dll` is not found and that is being searched for in different locations according to search order.

#Simple practical example

Since `p2pvoice.dll` doesn't exist we can create our own. For this we are going to use C++. C# dll libraries don't have straightforward way to run code as soon as dll is attached.

To create new dll in visual studio 2017 we go to:

~~~text
New Project  -> Visual C++\Windows Desktop\Dynamic-Link Library(DLL)
~~~

We can name project according to dll we want to create.
For simple example we are just going to edit `dllmain.cpp` to: 

~~~C
#include <windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
	WinExec("calc", 0);
    return TRUE;
}
~~~

This will just start windows calculator whenever dll is attached and detached to process or thread. After building solution generated dll is going to be placed in `Debug` folder. To finish with dll injection we can just copy it to CS game folder.

Now if we start hl.exe we are also going to get tons of calc.exe processes opening.

Have fun.