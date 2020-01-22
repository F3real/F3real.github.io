Title: Implicit dll linking
Date: 2019-4-14 10:01
Modified: 2019-4-14 10:01
Category: tutorial
Tags: windows, dll, lib
Slug: implicit_dll_linking
Authors: F3real
Summary: How to implicitly link dll

In windows, we can link dlls in two different ways to our program, implicitly and explicitly.

In explicit linking, during runtime of our program, we make a call to `LoadLibrary` or similar function to obtain module handle.

In implicit linking, we link our program to `.lib` file and include headers containing declarations of exported data and functions.

Now interestingly Windows has two types of `.lib` files. Usually, they represent static libraries and linking them copies code stored in them to our executable. The second type of `.lib` files in Windows are import libraries that contain only stub code of dll functions and make our executable load required dll at startup.

So how to create required import `.lib` file from dll?

First, we have to get a list of exported functions from dll. For this, we can use `dumpbin` utility included with visual studio.
In Visual Studio 2017 path to dumpbin is:
~~~text
\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.13.26128\bin\Hostx64\x64\dumpbin.exe
~~~

To use dumpbin:
~~~text
PS>dumpbin.exe /exports C:\Windows\SysWOW64\netapi32.dll
Microsoft (R) COFF/PE Dumper Version 14.13.26132.0
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file C:\Windows\SysWOW64\netapi32.dll

File Type: DLL

  Section contains the following exports for NETAPI32.dll

    00000000 characteristics
    171B77B1 time date stamp
        0.00 version
           1 ordinal base
         296 number of functions
         296 number of names

    ordinal hint RVA      name

          1    0          DavAddConnection (forwarded to ext-ms-win-rdr-davhlpr-l1-1-0.DavAddConnection)
          2    1          DavDeleteConnection (forwarded to ext-ms-win-rdr-davhlpr-l1-1-0.DavDeleteConnection)
          3    2          DavFlushFile (forwarded to ext-ms-win-rdr-davhlpr-l1-1-0.DavFlushFile)
          4    3          DavGetExtendedError (forwarded to ext-ms-win-rdr-davhlpr-l1-1-0.DavGetExtendedError)
          ....
          long list of exported functions
          ....
~~~

The hint is used by the loader as an attempt to find the location of function faster.
Now to create lib file we have first to create an export definition file (`.def`). The standard form of def file is:

~~~text
LIBRARY   ourdll.dll
EXPORTS
   funcName1
   funcName2
~~~

To generate lib file itself we use lib.exe utility (located in the same folder as dumpbin). Let's do this on example `.def` file:

~~~text
PS> cat mylib.def
LIBRARY   netapi32.dll
EXPORTS
   DavAddConnection
   DavDeleteConnection

PS> lib.exe /def:mylib.def /machine:x64
Microsoft (R) Library Manager Version 14.13.26132.0
Copyright (C) Microsoft Corporation.  All rights reserved.

   Creating library mylib.lib and object mylib.exp
~~~

Executables linked to `.lib` files created in this way contain strings of function names exported from dll. To remove these strings we can use ordinal import. In `.def` files we need to add an ordinal number of function after function name (funcName1 @ordNumber).


~~~text
PS> cat mylib.def
LIBRARY   netapi32.dll
EXPORTS
   DavAddConnection @1
   DavDeleteConnection @2

PS> lib.exe /def:mylib.def /out:mylib2.lib /machine:x64
Microsoft (R) Library Manager Version 14.13.26132.0
Copyright (C) Microsoft Corporation.  All rights reserved.

   Creating library mylib2.lib and object mylib2.exp  
~~~

The ordinal represents the position of the function's address pointer in the DLL Export Address table. Ordinal values for Windows API functions don't have to be exactly the same between different Windows versions so they are not the most reliable way to import functions from dlls. But on the upside, this way of importing also provides a slight performance increase.