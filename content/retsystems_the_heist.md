Title: Ret2 systems wargame
Date: 2019-1-25 10:01
Modified: 2019-1-25 10:01
Category: ctf
Tags: ctf, reversing, assembly
Slug: Ret2systems_theheist
Authors: F3real
Summary: How to solve Ret2systems the heist

This is simple reversing challenge hosted [here](https://wargames.ret2.systems/level/shmoo).

Site offers pretty nice interface with GDB, dissasembly view and python shell.

We are given part of source code:
~~~c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// hidden files
#include "wargames.h"
#include "shmoo.h"

void main(int argc, char * argv[]) 
{
    init_wargame();

    printf("------------------------------------------------------\n");
    printf("--[ ShmooCon 2019 - Coffee Cup Lockbox                \n");
    printf("------------------------------------------------------\n");
 
    char pin[32] = {};
    char * seed = argv[1]; // provided by server, unique per user

	// Prompt the user to enter the secret lockbox PIN
	printf("ENTER PIN: ");
	fgets(pin, sizeof(pin), stdin);
	pin[strcspn(pin, "\n")] = 0;

    // Check if the given PIN is valid for the RET2 lockbox
    if (validate_pin(pin, seed))
        validation_failure();
    else
        unlock_door();
}
~~~

We see that we need to reverse `validate_pin` function. Let's look at the assembly code of this function:

~~~asm
;validate pin
0x4009f6:  push    rbp
0x4009f7:  mov     rbp, rsp
0x4009fa:  sub     rsp, 0x20
0x4009fe:  mov     qword [rbp-0x18], rdi
0x400a02:  mov     qword [rbp-0x20], rsi
0x400a06:  mov     rax, qword [rbp-0x18]
0x400a0a:  mov     rdi, rax
0x400a0d:  call    is_valid_length
0x400a12:  test    eax, eax
0x400a14:  jne     0x400a25
0x400a16:  mov     dword [rel g_error], 0x1
0x400a20:  jmp     0x400abb
0x400a25:  mov     rax, qword [rbp-0x18]
0x400a29:  mov     rdi, rax
0x400a2c:  call    is_numeric_string
0x400a31:  test    eax, eax
0x400a33:  jne     0x400a41
0x400a35:  mov     dword [rel g_error], 0x2
0x400a3f:  jmp     0x400abb
0x400a41:  mov     dword [rbp-0x10], 0x0
0x400a48:  mov     rax, qword [rbp-0x20]
0x400a4c:  mov     edx, 0xa
0x400a51:  mov     esi, 0x0
0x400a56:  mov     rdi, rax
0x400a59:  call    strtoul
0x400a5e:  mov     dword [rbp-0x8], eax
0x400a61:  mov     rax, qword [rbp-0x18]
0x400a65:  mov     edx, 0xa
0x400a6a:  mov     esi, 0x0
0x400a6f:  mov     rdi, rax
0x400a72:  call    strtoul
0x400a77:  mov     dword [rbp-0x4], eax
0x400a7a:  mov     eax, dword [rbp-0x8]
0x400a7d:  xor     eax, dword [rbp-0x4]
0x400a80:  mov     dword [rbp-0x10], eax
0x400a83:  mov     dword [rbp-0xc], 0x0
0x400a8a:  jmp     0x400a97
0x400a8c:  add     dword [rbp-0x10], 0x52455432
0x400a93:  add     dword [rbp-0xc], 0x1
0x400a97:  cmp     dword [rbp-0xc], 0x9
0x400a9b:  jle     0x400a8c
0x400a9d:  rol     dword [rbp-0x10], 0x10
0x400aa1:  xor     dword [rbp-0x10], 0xc011ec7
0x400aa8:  cmp     dword [rbp-0x10], 0xc0ffee
0x400aaf:  je      0x400abb
0x400ab1:  mov     dword [rel g_error], 0x3
0x400abb:  mov     eax, dword [rel g_error]
0x400ac1:  leave   
0x400ac2:  retn 
~~~

We also see it makes call to is `is_valid_length` function:
~~~asm
;is_valid_length
0x400966:  push    rbp
0x400967:  mov     rbp, rsp
0x40096a:  sub     rsp, 0x10
0x40096e:  mov     qword [rbp-0x8], rdi
0x400972:  mov     rax, qword [rbp-0x8]
0x400976:  mov     rdi, rax
0x400979:  call    strlen
0x40097e:  cmp     rax, 0xa                 ; len 10
0x400982:  sete    al
0x400985:  movzx   eax, al
0x400988:  leave   
0x400989:  retn    
~~~

This is simple function calling `strlen` and checking if length is 10.

If we look at register values during `strtoul` calls we see that `qword [rbp-0x20]` is `seed` and that `qword [rbp-0x18]` is our input. Both get converted from string to 32 bit int. 

After conversion to int, `seed` gets saved to `dword [rbp-0x8]` and our input to `dword [rbp-0x4]`.

We can use GDB they provided to read `seed` value.

If we look at rest of function we see that we have loop which adds `0x52455432` 10 times after which we `rol`, `xor` and finally comparison with `0xc0ffee`.

We can write C program to follow these steps backwards and generate required input.

~~~c
#include <stdio.h>
#include <stdint.h>

int main()
{
    uint32_t res1 = 0xc0ffee ^ 0xc011ec7;
    uint32_t res2 = 0;
    uint32_t seed = 0x3273b96d;
    __asm(
        "ror $0x10, %1;"
        :"=r"(res2)
        :"r"(res1)
    );
    uint32_t inputXor =  res2 - (0x52455432 * 10);
    uint32_t input =  inputXor ^ seed;

    printf("Potential input: %u\n", input);
    return 0;
}
~~~