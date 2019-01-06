Title: Pwn Adventure Sourcery part 2
Date: 2019-1-4 10:01
Modified: 2019-1-4 10:01
Category: ctf
Tags: ctf, reversing, assembly,
Slug: pwnadventure_sourcery2
Authors: F3real
Summary: How to solve Pwn Adventure Sourcery swamp challenges

In this writeup we will take a look at second lab door and swap maze entrace challenges.

[TOC]

## Lab door 2

Lets get the source code:

~~~asm
TERMINAL_INPUT = 0
TERMINAL_OUTPUT = 1
DOOR_CONTROL = 2

main:
.correct_pin = 0

.main_loop:
	call ask_and_verify_code
	test al, al
	jz .invalid

	call open_door
	jmp .main_loop

.invalid:
	; Show denied message
	mov esi, invalid
	mov ecx, end_invalid - invalid
	mov dx, TERMINAL_OUTPUT
	rep outsb

	call sleep
	jmp .main_loop


ask_and_verify_code:
; Variables
.input = -32
.len = -36

	push esi
	push edi
	push ebp
	mov ebp, esp
	sub esp, 36

	mov dword [ebp + .len], 0

	; Display initial message
	mov esi, message
	mov ecx, end_message - message
	mov dx, TERMINAL_OUTPUT
	rep outsb

.input_loop:
	; Grab next input
	in al, TERMINAL_INPUT

	; If enter is pressed, done
	cmp al, '\n'
	je .end_input

	; Look for backspace
	cmp al, 8
	je .backspace

	; Printable only
	cmp al, ' '
	jb .input_loop
	cmp al, '~'
	ja .input_loop

	; Add character to input
	mov ecx, [ebp + .len]
	cmp ecx, 31
	jae .input_loop

	mov [ebp + .input + ecx], al
	inc dword [ebp + .len]
	out TERMINAL_OUTPUT, al
	jmp .input_loop

.backspace:
	cmp dword [ebp + .len], 0
	je .input_loop

	; Erase last character
	mov al, 8
	out TERMINAL_OUTPUT, al
	mov al, ' '
	out TERMINAL_OUTPUT, al
	mov al, 8
	out TERMINAL_OUTPUT, al

	dec dword [ebp + .len]
	jmp .input_loop

.end_input:
	out TERMINAL_OUTPUT, al

	; Null terminate input
	mov ecx, [ebp + .len]
	mov byte [ebp + .input + ecx], 0

	; Check code
	lea eax, [ebp + .input]
	push eax
	call verify_code

	mov esp, ebp
	pop ebp
	pop edi
	pop esi
	ret


verify_code:
	push esi
	push ebp
	mov ebp, esp
	sub esp, 8

	push dword [ebp + 12]
	call strlen
	cmp eax, 16                              ;length has to be 16
	jne .bad

	mov esi, [ebp + 12]                      ;load input to esi
	;initialization
	mov edx, 0xfa
	mov al, [esi]                            ;load first char from input
	rol edx, 5                               ;like shift but shifted bits 
	xor dl, al                               ;are rotated to the other end

	add dl, 0xab
	mov al, [esi+1]
	rol edx, 3
	xor dl, al

	add dl, 0x45
	mov al, [esi+2]
	rol edx, 1
	xor dl, al

	add dl, 0x12
	mov al, [esi+3]
	rol edx, 9
	xor dl, al
	;calculate remaining characters based on first four
	add dl, 0xcd
	mov cl, dl
	and cl, 15
	add cl, 'a'
	cmp [esi+4], cl
	jne .bad
	rol edx, 12
	xor dl, cl

	add dl, 0x87
	mov cl, dl
	and cl, 15
	add cl, 'a'
	cmp [esi+5], cl
	jne .bad
	rol edx, 3
	xor dl, cl

	add dl, 0xef
	mov cl, dl
	and cl, 15
	add cl, 'C'
	cmp [esi+6], cl
	jne .bad
	rol edx, 1
	xor dl, cl

	add dl, 0x10
	mov cl, dl
	and cl, 15
	add cl, 'f'
	cmp [esi+7], cl
	jne .bad
	rol edx, 13
	xor dl, cl

	add dl, 0x9a
	mov cl, dl
	and cl, 15
	add cl, 'e'
	cmp [esi+8], cl
	jne .bad
	rol edx, 9
	xor dl, cl

	add dl, 0xa8
	mov cl, dl
	and cl, 15
	add cl, 'D'
	cmp [esi+9], cl
	jne .bad
	rol edx, 7
	xor dl, cl

	add dl, 0xca
	mov cl, dl
	and cl, 15
	add cl, 'D'
	cmp [esi+10], cl
	jne .bad
	rol edx, 2
	xor dl, cl

	add dl, 0x91
	mov cl, dl
	and cl, 15
	add cl, 'c'
	cmp [esi+11], cl
	jne .bad
	rol edx, 5
	xor dl, cl

	add dl, 0x86
	mov cl, dl
	and cl, 15
	add cl, 'A'
	cmp [esi+12], cl
	jne .bad
	rol edx, 6
	xor dl, cl

	add dl, 0xf1
	mov cl, dl
	and cl, 15
	add cl, 'e'
	cmp [esi+13], cl
	jne .bad
	rol edx, 3
	xor dl, cl

	add dl, 0x1f
	mov cl, dl
	and cl, 15
	add cl, 'B'
	cmp [esi+14], cl
	jne .bad
	rol edx, 4
	xor dl, cl

	add dl, 0x90
	mov cl, dl
	and cl, 15
	add cl, 'f'
	cmp [esi+15], cl
	jne .bad

	mov al, 1
	mov esp, ebp
	pop ebp
	pop esi
	ret 4

.bad:
	xor al, al
	mov esp, ebp
	pop ebp
	pop esi
	ret 4


strlen:
	xor eax, eax
	mov ecx, [esp + 4]
.loop:
	mov dl, [ecx]
	test dl, dl
	jz .end
	inc eax
	inc ecx
	jmp .loop
.end:
	ret 4


open_door:
	push esi

	; Send command to unlock door
	mov al, 1
	out DOOR_CONTROL, al

	; Show open message
	mov esi, open
	mov ecx, end_open - open
	mov dx, TERMINAL_OUTPUT
	rep outsb

	call sleep

	pop esi
	ret


sleep:
	mov ecx, 120
.sleep_loop:
	pause
	loop .sleep_loop
	ret


message:
	db "\fCLEARENCE LEVEL 2 REQUIRED\nAuthorization code:\n"
end_message:

open:
	db "ACCESS GRANTED"
end_open:

invalid:
	db "ACCESS DENIED"
end_invalid:
~~~

If we look at the `verify_code` function carefully we see, that key is calculated based on first 4 characters. There is a lot of code, but basically there are just 2 unrolled for loops. If you don't want to look at assembly C solver will give you good overview of way in which key is being calculated.

But still this challenge took some time to solve mostly due to bug caused by not properly emulating 8 bit addition. To track it down I actually had to write inline assembly version of the same code.

C solver:

~~~c
#include <stdio.h>
#include <stdint.h>

uint8_t input[] = {'a', 'a', 'a', 'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

uint8_t hardcoded_add[] = {0xfa, 0xab, 0x45, 0x12, 0xcd, 0x87, 0xef, 0x10, 0x9a, 
0xa8, 0xca, 0x91, 0x86, 0xf1, 0x1f, 0x90};
uint8_t hardcoded_roll[] = {5, 3, 1, 9, 12, 3, 1, 13, 9, 7, 2, 5, 6, 3, 4, 0};
uint8_t hardcoded_add2[] = {'a', 'a', 'C', 'f', 'e', 'D', 'D', 'c', 'A', 'e', 'B', 'f'};

uint32_t rotl32 (uint32_t n, unsigned int c)
{
  const unsigned int mask = (8*sizeof(n) - 1);
  c &= mask;
  return (n<<c) | (n>>( (-c)&mask ));
}

int main()
{
    int i = 0;
    uint32_t tmp = 0;
    
    for(i=0; i<4; i++){
        tmp = tmp + hardcoded_add[i];
        tmp = rotl32(tmp, hardcoded_roll[i]); 
        tmp = tmp ^ input[i];
    }

    for(i=4; i<16; i++){
        tmp = (0xFFFFFF00 & tmp)+ ((tmp + hardcoded_add[i]) & 0xFF);
        uint8_t test1 = tmp & 15;
        test1 = test1 + hardcoded_add2[i-4];
		input[i] = test1;
        tmp = rotl32(tmp, hardcoded_roll[i]);
        tmp = tmp ^ test1;
    }

    for(i=0; i<16; i++){
        printf("%c", input[i]);
    }
    printf("\n");
    return 0;
}
~~~

Solution: `aaaaohFgqNRnHeBt`

Inline assembly version:
~~~c
#include <stdio.h>
#include <stdint.h>

uint8_t input[] = {'a', 'a', 'a', 'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

uint8_t hardcoded_add[] = {0xfa, 0xab, 0x45, 0x12, 0xcd, 0x87, 0xef, 0x10, 0x9a, 
0xa8, 0xca, 0x91, 0x86, 0xf1, 0x1f, 0x90};
uint8_t hardcoded_roll[] = {5, 3, 1, 9, 12, 3, 1, 13, 9, 7, 2, 5, 6, 3, 4, 0};
uint8_t hardcoded_add2[] = {'a', 'a', 'C', 'f', 'e', 'D', 'D', 'c', 'A', 'e', 'B', 'f'};

uint32_t rotl32 (uint32_t n, unsigned int c)
{
  const unsigned int mask = (8*sizeof(n) - 1);
  c &= mask;
  return (n<<c) | (n>>( (-c)&mask ));
}

int main()
{
    int i = 0;
    uint32_t tmp = 0;
    
    for(i=0; i<4; i++){
        asm(
          	"add %1, %%dl;"
          	"mov %2, %%al;"
          	"roll %3, %%edx;"
          	"xor %%al, %%dl;"
           :"+d"(tmp)
           :"r"(hardcoded_add[i]), "r"(input[i]), "cI"(hardcoded_roll[i])
           :"eax"
        );
    }

    for(i=4; i<16; i++){
        asm(
           "add %1, %%dl;"
           :"+d"(tmp)
           :"r"(hardcoded_add[i])
        );
        uint8_t test1 = 0;
        asm(
           "mov %2, %%edx;"
           "mov %%dl, %%cl;"
           "and $15, %%cl;"
           "add %1, %%cl;"
           "mov %%cl, %0;"
           :"=r"(test1)
           :"r"(hardcoded_add2[i-4]), "r"(tmp)
           :"eax", "ecx", "edx"
        );
        input[i] = test1;       
        tmp = rotl32(tmp, hardcoded_roll[i]);
        asm(
           "xor %1, %%dl;"
           :"+d"(tmp)
           :"r"(test1)
       );
    }


    for(i=0; i<16; i++){
        printf("%c", input[i]);
    }
    printf("\n");
    return 0;
}
~~~

Btw, there is also cave filled with spiders north from the desert with boss to beat :D

![Spider boss]({static}/images/2018_4_1_sourcery.png){: .img-fluid .centerimage}

## Lab door 3

Source code of third lab door has ~6k lines of code. But fortunately most of it is in `decipher` function and represents unrolled loop.

Full source code can be found [here](https://github.com/F3real/ctf_solutions/blob/master/2018/pwn_adventure_sourcery/LabDoor3/LabDoor3.asm)

Lets look at important few code snippets:

~~~asm
	; read in the input, expect "XXXXXXXX-XXXXXXXX"
	mov     edi, inbuf
	call    input

	; check input format
	mov		esi, inbuf
	cmp		byte [esi+8], '-'
	jne		.fail
	mov		byte [esi+8], 0

	; parse first ctext
	push	v0
	push	inbuf
	call	parse_uint32_hex
	cmp		eax, -1
	je		.fail

	; parse second ctext
	push	v1
	push	inbuf+9
	call	parse_uint32_hex
	cmp		eax, -1
	je		.fail

	; decipher
	push	v0
	call	decipher

	; check
	cld                         ; clear direction flag so that string pointers auto increment after each string operation
	mov		esi, v0             
	lodsd                       ; load string instructions (loads to EAX)
	cmp		eax, 0x57415343		; 'CSAW'
	jne		.fail
	lodsd
	cmp		eax, 0x41484148		; 'HAHA'
	jne		.fail

...

decipher:
	push   ebp                    ; esp - 4
	mov    ebp,esp
	push   esi
	push   ebx

	mov    ecx,dword [ebp+0x8]    ; input address
	mov    edx,dword [ecx]        ; first part of input     i0 = y1
	mov    esi,dword [ecx+0x4]    ; second part of input    i1 = y0
	mov    eax,edx                
	mov    ebx,edx
	shr    ebx,0x5                ; y0 >> 5 
	shl    eax,0x4                ; y0 << 4 
	xor    eax,ebx                
	add    eax,edx
	xor    eax,0x2913260a         
	sub    esi,eax                ; y2 = y0 - ((y1 >> 5) ^ (y1 << 4) + y1 ) ^ v0
	
    mov    ebx,esi
	mov    eax,esi
	shr    esi,0x5
	shl    ebx,0x4
	xor    ebx,esi
	add    ebx,eax
	xor    ebx,0x37dbdd6f        
	sub    edx,ebx               ; y3 = y1 - ((y2 >> 5) ^ (y2 << 4) + y2 ) ^ v1

~~~

Looking at the algorithm used for pin derivation, we see that it calculates each new step based on two previous ones. Since in the end results are compared to `0x57415343` and `0x41484148`, results of two last steps, we have everything we need to run derivation backwards and get required inputs.

Python solver:
~~~python
x = 0x57415343
y = 0x41484148

def step(x):
    return (((x >> 5)^(x<<4)) + x) & 0xffffffff

for val in values[::-1]:
    tmp = (x + (step(y) ^ val)) & 0xffffffff
    x = y
    y = tmp

print("0x%X  0x%X" %(x, y))
~~~

Full code can be found [here](https://github.com/F3real/ctf_solutions/blob/master/2018/pwn_adventure_sourcery/LabDoor3/sol.py)

Some things to note:

* inputs are taken in reverse order, first part of input is used as y1 and second as y0
* program treats inputted string as hex number

Calculated pin: `9b916917-b6117336`

## Swamp maze entrace

After we enter ruins we see robot we can program. Source code of robot:
~~~asm
INPUT = 0

main:
	mov esi, program
.loop:
	in al, INPUT
	cmp al, 0
	je .done
	mov [esi], al
	inc esi
	jmp .loop
.done:
	mov eax, SYS_DISCONNECT
	int 0x80
	mov eax, SYS_ROM_UPDATE
	mov ebx, program
	mov ecx, esi
	sub ecx, ebx                ;get length of program
	int 0x80

.data
program:
~~~

It executes input we pass to it. To solve this challenge we can use `SYS_WALK` syscall. 
~~~asm
  mov eax, SYS_WALK
  mov ebx, x  ; x-vel
  mov ecx, y  ; y-vel
  int 0x80
  hlt
~~~
But we can't use null byte since it is used to trigger execution. 
So we have to change `mov eax, SYS_WALK` with `xor eax, eax; mov al, SYS_WALK`. Also we don't need y-vel so we will set ecx to 0 with `xor ecx, ecx` and in ebx we will write max value (-1)

Solution:
~~~asm
mov esi, data
mov ecx, end-data
mov dx, 0
rep outsb
hlt

data:
xor eax, eax
xor ecx, ecx
mov al, SYS_WALK
mov ebx, -1
int 0x80
hlt
db 0                  ;starts execution
end:
~~~