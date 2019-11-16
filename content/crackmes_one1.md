Title: Crackmes one Mexican
Date: 2019-11-9 10:02
Modified: 2019-11-9 10:02
Category: reversing
Tags: reversing, crackme, windows, radare2 
Slug: crackmes_one1
Authors: F3real
Summary: Solutions to Mexican crackme

Recently, I've found interesting [post](https://medium.com/syscall59/solved-solving-mexican-crackme-82d71a28e189) about solving [Mexican](https://crackmes.one/crackme/5d63011533c5d46f00e2c305) crackme.

Let's look in depth how solution works and how is it automatically solving this crackme with radare2 and python.

To analyze binary we can use:

~~~
radare2 Untitled1.exe
~~~

We can analyze all symbols and entry points with `aa`. After this we can list functions using `afl` (all functions list).

With `s main` (seek) we can position ourself at start of main and we can disassemble function with `pdf` (print disassembly of function).
We can also use `pdf @main`.

Disassembly:
~~~asm
│   int main (int argc, char **argv, char **envp);
│           ; var int32_t var_1ch @ esp+0x1c
│           ; CALL XREF from entry0 @ 0x4013dd
│           0x0040162c      55             push ebp
│           0x0040162d      89e5           mov ebp, esp
│           0x0040162f      83e4f0         and esp, 0xfffffff0
│           0x00401632      83ec20         sub esp, 0x20
│           0x00401635      e886090000     call sym.___main
│           0x0040163a      c744241cc100.  mov dword [var_1ch], 0xc1   ; [0xc1:4]=-1 ; 193
│           0x00401642      817c241cc100.  cmp dword [var_1ch], 0xc1
│       ┌─< 0x0040164a      7e07           jle 0x401653
│       │   0x0040164c      e8affeffff     call sym flag()             ; sym.flag
│      ┌──< 0x00401651      eb0c           jmp 0x40165f
│      │└─> 0x00401653      c70424034040.  mov dword [esp], str.try_harder ; [0x404003:4]=0x20797274 ; "try harder"
│      │    0x0040165a      e8d9100000     call sym._printf            ; int printf(const char *format)
│      │    ; CODE XREF from main @ 0x401651
│      └──> 0x0040165f      b800000000     mov eax, 0
│           0x00401664      c9             leave
└           0x00401665      c3             ret
~~~

We see that it will compare 0xc1 with 0xc1 which will always go to fail condition.
If we look at function flag with `pdf @sym.flag`, we see:

~~~asm
┌ (fcn) sym.flag 300
│   sym.flag ();
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_4h @ esp+0x4
│           ; CALL XREF from main @ 0x40164c
│           0x00401500      55             push ebp
│           0x00401501      89e5           mov ebp, esp
│           0x00401503      83ec28         sub esp, 0x28
│           0x00401506      c704241d0000.  mov dword [esp], 0x1d       ; [0x1d:4]=-1 ; 29
│           0x0040150d      e8ee110000     call sym._malloc            ;  void *malloc(size_t size)
│           0x00401512      8945f4         mov dword [var_ch], eax
│           0x00401515      8b45f4         mov eax, dword [var_ch]
│           0x00401518      c60066         mov byte [eax], 0x66        ; 'f'
│                                                                      ; [0x66:1]=255 ; 102
│           0x0040151b      8b45f4         mov eax, dword [var_ch]
│           0x0040151e      83c001         add eax, 1
│           0x00401521      c6006c         mov byte [eax], 0x6c        ; 'l'
│                                                                      ; [0x6c:1]=255 ; 108
│           0x00401524      8b45f4         mov eax, dword [var_ch]
│           0x00401527      83c002         add eax, 2
│           0x0040152a      c60061         mov byte [eax], 0x61        ; 'a'
│                                                                      ; [0x61:1]=255 ; 97
│           0x0040152d      8b45f4         mov eax, dword [var_ch]
│           0x00401530      83c003         add eax, 3
│           0x00401533      c60067         mov byte [eax], 0x67        ; 'g'
│                                                                      ; [0x67:1]=255 ; 103
...
...
~~~

It will add all chars of flag to array and print them. So lets take a look at solution 1. We need to have r2pipe installed (`pip install r2pipe`).

~~~python
#!/usr/bin/env python3

import r2pipe

r = r2pipe.open("Untitled1.exe")

# 'analyze all" (all symbols and entry-points)
r.cmd("aa")
# seek to symbol 'flag'
r.cmd("s sym.flag")
# print dissembly of function
r.cmd("pdf")
# configure radare2 search engine to search in given range
r.cmd("e search.from = 0x00401500")
r.cmd("e search.to = 0x0040162b")
# search hexadecimal value
r.cmd("/x c600")

flag = bytearray()
# Print hex px, 
# j suffix can be used in most of the radare2 commands to get a JSON output
# pxj 3 - print 3 hex bytes in JSON format
# @@ used for looping
for byte_triplet in r.cmd("pxj 3 @@hit0").split('\n'):
    try:
        byte_triplet = eval(byte_triplet)
        flag.append(byte_triplet[2])
    except Exception as e:
        pass
print(f"FLAG: {flag}")
~~~

We will set search range to function we want to analyse and then search for all move eax instructions (`c600xx move eax, xx`) and extract byte being moved.

Solution 2, we can patch `cmp` instruction so that program will print the flag for us.

~~~python
#!/usr/bin/env python3

import r2pipe
import subprocess

subprocess.call(["cp", "./Untitled1.exe", "Cracked.exe"])

# Open file in write mode
r = r2pipe.open("Cracked.exe", ['-w'])

r.cmd('aa')

def print_addr_content(addr):
    r.cmd(f"s {addr}")
    print(f"Current disas of line at {addr}: {r.cmd('pd 1 ~[3-6]')}")
    print(f"Current bytecode of line at {addr}: {r.cmd('pd 1 ~[2]')}")
    out = list(map(hex, eval(r.cmd("pxj 6"))))
    print(f"Values at {addr}: {out}")
    r.cmd(f"s -")

print_addr_content(0x00401642)

print("[!] PATCHING BINARY")
# seek to address
r.cmd("s 0x00401642+4")
r.cmd("px 1")
# w1 write byte
# - decrement
# 1 (how many bytes to decrement)
r.cmd("w1- 1")
r.cmd("px 1")
r.cmd("s 0x00401642")
print("[!] BINARY PATCHED")

print_addr_content(0x00401642)
~~~

After this we can simply run patched binary to get the flag.
Both solutions are really nice way to get more familiar with radare2 scripting.