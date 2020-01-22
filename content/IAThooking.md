Title: IAT hooking
Date: 2019-4-17 10:01
Modified: 2019-4-17 10:01
Category: tutorial
Tags: windows, dll, IAT, hook
Slug: iat_hooking
Authors: F3real
Summary: How to do simple IAT hook

There are few different userland API hooking techniques in Windows, but in this post, we will take a look at IAT (Import Address Table) hooking.

IAT is a lookup table of function pointers for functions imported from modules (executables or dlls). At compile time addresses of these functions are unknown so dynamic linker/loader has to fill IAT with real function addresses at runtime.

IAT hooking relies on replacing real function address in IAT table with address we control. IAT doesn't work with functions obtained from dlls by `LoadLibrary`/`GetProcAddress` directly (but we can overwrite `GetProcAddress` to give different result).

Standard function call using IAT table looks something like:
~~~text
                Application                                               mydll
           +-------------------+                                  +--------------------+
           |                   |                                  |       func1        |
           |                   |                    +------------>---------------------+
           | call mydll!func1+ |               IAT  |             |  ....              |
           |                 | |       +-------------------+      |  code              |
           +-------------------+       |            |      |      |  ....              |
                             +----------> jmp func1 +      |      +--------------------+
                                       |                   |      |                    |
                                       +-------------------+      +--------------------+
~~~

The first step is to locate IAT in memory, for this we can parse PE optional header which contains `Data directory` entry with IAT address.

Here is pretty nice illustration of PE structure (taken from pentest.blog):

![PE structure]({static}/images/2019_4_17_location-of-the-IAT.png){: .img-fluid .centerimage}

`DataDirectory` is an array of `IMAGE_DATA_DIRECTORY` structures:

~~~c
typedef struct _IMAGE_DATA_DIRECTORY {
   DWORD VirtualAddress;     // RVA of data
   DWORD Size;               // Size of the data in bytes
}IMAGE_OPTIONAL_HEADERS32, *PIMAGE_OPTIONAL_HEADERS32;
~~~

Pointer IAT is found at `DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]` entry.

But finding the IAT is not enough for hooking an API function. It contains only API addreses and in order to replace an API function address we need to know which entry belongs to the API function that we want to hook. For this, we have to look at IDT (pointer to IDT is in `DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]`).

IDT (Import Directory Table) table contains IMAGE_IMPORT_DESCRIPTOR entries with the following structure:

~~~c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;                        // 0 for terminating null import descriptor
        PIMAGE_THUNK_DATA   OriginalFirstThunk;         // The RVA of the import lookup table
    };
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;                           // address of dll name string
    PIMAGE_THUNK_DATA   FirstThunk;         // same as OriginalFirstThunk or, if bound, the RVA of the IAT. 
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
~~~

IDT contains entries for all dlls loaded by executable and is used by the loader to fill entries in IAT with real function addresses.

ILT (Import Lookup Table) contains a list of function names imported from the specified DLL. Entries of ILT are IMAGE_THUNK_DATA32 structs.

~~~c
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        LPBYTE  ForwarderString; 
        PDWORD  Function;
        DWORD   Ordinal;
        PIMAGE_IMPORT_BY_NAME AddressOfData;
    }
}
typedef _IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA;
typedef _IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA32;
~~~

Functions can be imported by name or by ordinal. For ordinal imports, the `Ordinal` field of the union in `IMAGE_THUNK_DATA` structure will have the most significant bit set to 1 and the ordinal number can be extracted from the least significant bits.

In the case of import by name, the structure holds a pointer to `IMAGE_IMPORT_BY_NAME` structure.

~~~c
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;            //used to find location of function faster
    BYTE Name[1];         //pointer to the function name
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
~~~

So how does all this work?

`FirstThunk` in IDT contains the RVA to the array of `IMAGE_THUNK_DATA` structures with the same length as the OriginalFirstThunk array.
The `OriginalFirstThunk` represents ILT, an array of names of imported functions (if they are not imported using ordinal value). The `FirstThunk` is an array of addresses of imported functions IAT (after they are bound, initially it's the same as `OriginalFirstThunk`).

The `OriginalFirstThunk` uses the `AddressOfData` element of the `IMAGE_THUNK_DATA` structure to point to `IMAGE_IMPORT_BY_NAME` structure that contains the `Name` element, function name. The `FirstThunk` uses the `Function` element of the `IMAGE_THUNK_DATA` structure, which points to the address of the imported function. When the executable is loaded, the loader goes through the `OriginalFirstThunk` array and finds all imported function names the executable is using. Then it calculates the addresses of the functions and populates the `FirstThunk` array so that real functions can be accessed.

As a refresher, RVA and VA are defined as:

**RVA** (relative virtual address). In an image file, the address of an item after it is loaded into memory, with the base address of the image file subtracted from it. The RVA of an item almost always differs from its position within the file on disk (file pointer).

In an object file, an RVA is less meaningful because memory locations are not assigned. In this case, an RVA would be an address within a section (described later in this table), to which a relocation is later applied during linking. For simplicity, a compiler should just set the first RVA in each section to zero.

~~~text
base address of module + RVA of PE element = linear address of PE element 
~~~

**VA** (virtual address). Same as RVA, except that the base address of the image file is not subtracted. The address is called a “VA” because Windows creates a distinct VA space for each process, independent of physical memory. For almost all purposes, a VA should be considered just an address. A VA is not as predictable as an RVA because the loader might not load the image at its preferred location.

So, let's look at required steps to do IAT hook:

1. Locate optional header in `.exe` we want to hook
2. Locate IDT of dll containing function we want to hook
3. Locate entry in ILT (pointed to from OriginalFirstThunk) with the name of a function we want to hook
4. Replace entry with the same index in IAT (pointed to from FirstThunk) with the address we control

Example VS 2017 project with IAT hook implementation (without checks if PE format is ok) can be found [here](https://github.com/F3real/ctf_solutions/tree/master/2019/processHider). To use dll we get we also need to inject it in memory of the target process.