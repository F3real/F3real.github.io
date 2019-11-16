Title: Crackmes one 7eRoM's 1st one challenge
Date: 2019-11-16 10:02
Modified: 2019-11-16 10:02
Category: reversing
Tags: crackme, windows, radare2, unicorn
Slug: crackmes_one2
Authors: F3real
Summary: Solutions to 7eRoM's 1st challenge crackme

Today we will take a look at this [crackme](https://crackmes.one/crackme/5cd7153f33c5d4419da55a36).

One of first things we notice if we open given exe in Ghidra is:

~~~c
  local_414 = *(uint *)(*(int *)(*(int *)(in_FS_OFFSET + 0x18) + 0x30) + 2) & 0xff;
  ...
  ...
  if (local_414 == 0) {
      ....
  }
~~~

This is actually anti-debugger trick which diverts execution to false password check way if it detects debugger.

~~~asm
mov eax, large fs:18h ; Offset 18h has self-pointer to TEB
mov eax, [eax+30h] ; Offset 30h has pointer to PEB
movzx eax, byte ptr[eax+2] ; PEB.BeingDebugged
test eax, eax
~~~

This is equivalent to `IsDebuggerPresent` call.
The TIB (Thread Information Block) of the current thread can be accessed as an offset of segment register FS for Win32. It is common to first get a linear self-referencing pointer to it stored at FS:[0x18].
On offset 0x30 of TIB we have pointer to PEB (Process Environment Block). From there with offset 0x02 we can access `BeingDebugged` flag. `BeingDebugged` flag is set to 1 if process is being debugged, 0 otherwise.

To bypass this check we can use radare2 and just patch it:
~~~text
radare2.exe  -w CrackMe_1.exe
[0x004075a5]> s   0x00403b3c
[0x00403b3c]> pd 6
            0x00403b3c      81e2ff000000   and edx, 0xff               ; 255
            0x00403b42      89542414       mov dword [esp + 0x14], edx
            0x00403b46      e825e5ffff     call 0x402070
            0x00403b4b      e8d0e9ffff     call 0x402520
            0x00403b50      6a06           push 6                      ; 6
            0x00403b52      e818380000     call 0x40736f
[0x00403b3c]> "wa xor edx, edx; nop; nop; nop; nop;"
Written 6 byte(s) (xor edx, edx; nop; nop; nop; nop;) = wx 31d290909090
[0x00403b3c]> pd 6
            0x00403b3c      31d2           xor edx, edx
            0x00403b3e      90             nop
            0x00403b3f      90             nop
            0x00403b40      90             nop
            0x00403b41      90             nop
            0x00403b42      89542414       mov dword [esp + 0x14], edx
[0x00403b3c]>
~~~

After this change we can use simply debug given exe. I used x64dbg. We can just run app to password prompt, pause executing enter password and run to user code.

![x64dbg]({static}/images/2019_11_16_debugger.png){: .img-fluid .centerimage}

One interesting detail is that program is using [Ftring](https://github.com/7eRoM/Ftring) to encrypt strings. Ftring will generate instructions to set flags corresponding to given letter and then use `lahf` instruction to transfer them to `al` register. For example to generate letter `A` following instruction sequence will be used:
~~~asm
		xor al, al

		mov cl, 225
		add cl, 9
		setc bl
		xor al, bl
		shl al, 1

		mov dl, 144
		dec dl
		lahf
		test ah, 10h
		jz RHpFexiD
		xor al, 1
		RHpFexiD:
		shl al, 1

		mov dh, 2
		inc dh
		setz bl
		xor al, bl
		shl al, 1

		mov edx, 803704434
		inc edx
		setp bl
		xor al, bl
		shl al, 1

		mov si, 27175
		sub si, 20613
		setz bl
		xor al, bl
		shl al, 1

		mov bl, 149
		add bl, 39
		setp bl
		xor al, bl
		shl al, 1

		mov dh, 59
		sub dh, 218
		lahf
		test ah, 10h
		jz IWsajNHQ
		xor al, 1
	IWsajNHQ:
		shl al, 1

		mov cx, 19329
		add cx, 16579
		setp bl
		xor al, bl

		// Writing char 'A' to memory
		mov byte ptr[static_array + 0], al
~~~
We can locate reasonably well ftring instruction sequences using radare2 with:
~~~text
"/a lahf; test ah, 0x10;"
~~~
Unfortunately, radare2 had trouble with `lahf` instruction but it turned to be very easy to [fix](https://github.com/radareorg/radare2/pull/15463). Just make sure to use latest version of radare2 (and git is recommended way to get radare2 anyway).

Once we extract instruction sequences we can use unicorn to emulate them and see what are they evaluating to. Example of using unicorn to decode fstring sequences is given bellow:

~~~python
from unicorn import *
from unicorn.x86_const import *

X86_CODE32_ARR = [ "32c0b61b80c66d0f92c332c3d0e0b27ffec20f98c332c3d0e0f90f92c332c3d0e0b2c680c23a0f92c332c3d0e0beb79c913081ee50a1e1150f92c332c3d0e0b580fecd0f98c332c3d0e066be2f5f66460f9ac332c3d0e066be0000664e0f98c332c3", "32c0b1aa80c1a70f98c332c3d0e0b1a0fec90f9ac332c3d0e0b200feca0f98c332c3d0e066ba6aba6681c22a810f9ac332c3d0e0b1c8fec10f94c332c3d0e066be0080664e0f98c332c3d0e0bf1a1c119e81c7e6e3ee610f94c332c3d0e066bafcdd6681c204220f94c332c3",
"32c0b3ad80eb9f0f94c332c3d0e066b9000066490f98c332c3d0e0bf697ca53381ef697ca5330f94c332c3d0e0b6f580eec90f98c332c3d0e0b1fb80e9560f92c332c3d0e0b267feca0f94c332c3d0e066b9b0276681c18ca59ff6c41074023401d0e0b1affec19ff6c41074023401",
"32c0f80f92c332c3d0e0b15180c16b0f98c332c3d0e066bfb9086681c707f89ff6c41074023401d0e0b157fec99ff6c41074023401d0e066bbffff66430f94c332c3d0e0bbbfdd791f4b0f9ac332c3d0e066bf67626681c75cd70f92c332c3d0e0badb2036c4420f94c332c3",
"32c0bffebb799e81effa67247f0f9ac332c3d0e066ba5782664a0f9ac332c3d0e0b63980eeaf9ff6c41074023401d0e066bbf0a26681ebc0dc9ff6c41074023401d0e0b580fecd0f98c332c3d0e0b9ffffff7f410f98c332c3d0e0b301fecb0f94c332c3d0e0ba2042c27b81ead42d50730f9ac332c3"]

ADDRESS = 0x1000000

for ftring_insc in X86_CODE32_ARR:
    try:
            ftring_insc_dec = bytes.fromhex(ftring_insc)
            # Initialize emulator in X86-32bit mode
            mu = Uc(UC_ARCH_X86, UC_MODE_32)

            # map 2MB memory for this emulation
            mu.mem_map(ADDRESS, 2 * 1024 * 1024)

            # write machine code to be emulated to memory
            mu.mem_write(ADDRESS, ftring_insc_dec)
            
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(ftring_insc_dec))

            r_al = mu.reg_read(UC_X86_REG_AL)
            print(f'>>> AL = {hex(r_al)} {chr(r_al)}')

    except UcError as e:
        print("ERROR: %s" % e)
~~~

I was kinda lazy and didn't finish it completely. To automate example more we could either map memory properly or implement handler that will skip store/read instructions and just print values from `al` when they are called.
