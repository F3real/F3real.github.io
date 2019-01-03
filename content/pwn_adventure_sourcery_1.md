Title: Pwn Adventure Sourcery part 1
Date: 2019-1-3 10:01
Modified: 2019-1-3 10:01
Category: ctf
Tags: ctf, reversing, assembly, binary exploitation, pwnable
Slug: pwnadventure_sourcery1
Authors: F3real
Summary: How to solve Pwn Adventure Sourcery start challenges

Pwn Adventure Sourcery is really interesting game made for CSAW finals 2018. Game was made using Rust and WebAssembly.

Commands are simple, we walk using arrow keys, interact using `E` key and use weapons/items with `SPACE` key. To play game properly we (sadly) need to use Chrome browser, otherwise `CTRL+C/CTRL+V` won't work which will make game much harder.

[TOC]

In brief tutorial, we see get assembly code for fire spell that we need to use to break builder standing in our way.
~~~asm
mov eax, SYS_FIRE
mov ebx, 16   ; energy to use
int 0x80
hlt
~~~

Going foward we get to `Spell extractor` which we can use to get source code of doors and our first challenge **Jail Storage Door**.

## Jail Storage Door

~~~asm
TERMINAL_INPUT = 0
TERMINAL_OUTPUT = 1
DOOR_CONTROL = 2

main:
	; Display initial message
	mov esi, message
	mov ecx, end_message - message
	mov dx, TERMINAL_OUTPUT
	rep outsb

.input_loop:
	; Grab next input
	in al, TERMINAL_INPUT             ;in dest, src
	cmp al, '0'              
	jb .input_loop                    ;Jump if Below (unsigned comparison)
	cmp al, '9'
	ja .input_loop                    ;Jump if Above (unsigned comparison)

	; Rolling code for last 4 digits
	mov cl, [entered_code + 1]
	mov [entered_code], cl
	mov cl, [entered_code + 2]
	mov [entered_code + 1], cl
	mov cl, [entered_code + 3]
	mov [entered_code + 2], cl
	mov [entered_code + 3], al

	; Display updated code
	mov dx, TERMINAL_OUTPUT
	mov al, '\r'
	out dx, al
	mov esi, entered_code
	mov ecx, 4
	rep outsb

	; Check code
	mov esi, correct_code
	mov edi, entered_code
	mov ecx, 4
	repe cmpsb
	je .open_door

	jmp .input_loop

.open_door:
	; Send command to unlock door
	mov al, 1
	out DOOR_CONTROL, al

	; Show open message
	mov esi, open
	mov ecx, end_open - open
	mov dx, TERMINAL_OUTPUT
	rep outsb

	jmp .input_loop

correct_code:
	db "5129"                         ;Solution

message:
	db "PIN code:\n"
end_message:

open:
	db "\rOPEN"
end_open:

.data
entered_code:
	db 0, 0, 0, 0
~~~

Only confusing part was way in which data was loaded in memory. Characters are loaded in last position in `entered_code` array and then moved towards first position after each new character is entered.

We also see that `correct_code` is hardcoded to `5129` which is our solution.

## Jail Door

Moving forward we get `Pwn tool` which we can use to write our own assembly code to interact with items.

~~~asm
TERMINAL_INPUT = 0
TERMINAL_OUTPUT = 1
SECURE_PIN_STORAGE = 2
DOOR_CONTROL = 3

main:
.correct_pin = 0
	sub esp, 32

	; Fetch PIN from secure memory
	lea edi, [esp + .correct_pin]
	push edi
	call get_secure_pin
	add esp, 4

.main_loop:
	push edi
	call ask_and_verify_pin
	add esp, 4
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


ask_and_verify_pin:
; Args
.correct_pin = 16
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
	in al, TERMINAL_INPUT                    ;read char from input

	; If enter is pressed, done
	cmp al, '\n'
	je .end_input

	; Look for backspace
	cmp al, 8
	je .backspace

	; Add character to input
	mov ecx, [ebp + .len]
	mov [ebp + .input + ecx], al
	inc dword [ebp + .len]                   ;The inc instruction increments the contents of its operand by one
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
	mov esi, [ebp + .correct_pin]
	lea edi, [ebp + .input]
	mov ecx, [ebp + .len]
	inc ecx
	repe cmpsb
	sete al

	mov esp, ebp
	pop ebp
	pop edi
	pop esi
	ret


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


get_secure_pin:
	mov ecx, [esp + 4]
.get_pin_loop:
	in al, SECURE_PIN_STORAGE
	mov [ecx], al
	inc ecx
	test al, al                            ;check if value is zero
	jnz .get_pin_loop
	ret


sleep:
	mov ecx, 120
.sleep_loop:
	pause
	loop .sleep_loop
	ret


message:
	db "\fPIN code:\n"
end_message:

open:
	db "ACCESS GRANTED"
end_open:

invalid:
	db "ACCESS DENIED"
end_invalid:
~~~

This time pin is read from secure storage and we can't see it in source code. The `input_loop` is pretty simple it reads a char, checks if it is backspace or return, increments number of chars and saves our input.

Since no checks are being made for length of input we have classic buffer overflow.
Let's see what's the offset to overwrite EIP.

~~~asm
	push eip           ;call will place EIP on stack
ask_and_verify_pin:
	push esi           ; esp - 4
	push edi           ; esp - 4
	push ebp           ; esp - 4
	mov ebp, esp
	sub esp, 36        ; esp - 36
~~~

We see that `esp + 48` will give us ability to overwrite EIP. Input starts from `ebp + .input`  that is `ebp - 32` or `esp + 4`.  This means that offset from input we control is `44` to EIP. Address of `open_door` function is 0x10a7.

Our assembly solution we need to write in `Pwn tool`:

~~~asm
mov esi, data
mov ecx, end-data
mov dx, 0
rep outsb
hlt

data:
db "11111111111111111111111111111111"
db "111111111111"
db 0xa7,0x10
db "\n"
end:
~~~

After leaving jail, we can go visit town (just north) and go right to zombie map. This part is just classic game, we need to kill zombie boss to unlock new spell. 

There are 3 buttons that need to be pressed to unlock boss room. Upon entering room with boss doors lock and fight is triggered but only if you move more then two steps from the door, which we can use to clear all other zombies before boss fight itself.

After the figt we get `Explode` spell:

~~~asm
	mov ecx, 24
wait:
	pause
	loop wait
	mov eax, SYS_EXPLODE
	mov ebx, 32
	int 0x80
	hlt 
~~~

Now we have to go back to map we entered after leaving jail and then left and down to enter desert area and down again to enter Lab.

## Lab Door 1

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
	cmp al, ' '                        ;above ' ' 0x20 and bellow ~ 0xFE
	jb .input_loop
	cmp al, '~'
	ja .input_loop

	; Add character to input
	mov ecx, [ebp + .len]
	cmp ecx, 31
	jae .input_loop                    ;if above 31 jmp input_loop; 31 max length

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
	cmp eax, 16                       ;length has to be 16
	jne .bad

	mov esi, [ebp + 12]               ;load eax (input)
	lea edx, [ebp - 8]                ;load eax again
	mov ecx, 8                        ;loop 8 times
.loop1:
	mov al, [esi]                      
	xor al, [esi + 8]                 ; xor input + (input + 8)
	mov [edx], al                     ; move result to input
	inc esi
	inc edx
	loop .loop1

	lea esi, [ebp - 8]
	mov edx, valid
	mov ecx, 8                        ;loop 8 times
.check:                               ;check if same as `valid` array
	mov al, [esi]
	cmp al, [edx]
	jne .bad
	inc esi
	inc edx
	loop .check

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

valid:
	db 0x09, 0x23, 0x06, 0x07, 0x36, 0x38, 0x22, 0x2c

message:
	db "\fCLEARENCE LEVEL 1 REQUIRED\nAuthorization code:\n"
end_message:

open:
	db "ACCESS GRANTED"
end_open:

invalid:
	db "ACCESS DENIED"
end_invalid:
~~~

We have another reversing challenge that we need to pass to unlock the door. Length of input is checked so we need to understand how the code works to bypass pink check. I have left some comments that should make code a bit clearer. 

Basically we can only enter characters between `' '` and `~`. Length of input has to be 16 and each of the first eight characters from input are XORed with the input characters 8 positions ahead from them. Result we get is then checked with `valid` array.

Bruteforce python solution:

~~~python
alphabet = [x for x in range(0x20, 0xFE + 1)]
values = [0x09, 0x23, 0x06, 0x07, 0x36, 0x38, 0x22, 0x2c]

for val in values:
  for x in alphabet:
    for y in alphabet:
      if x ^ y == val:
        print("%x (%c) ^ %x (%c)= %x" % (x, chr(x), y, chr(y), val))
        continue

# Verify solution
sol = [0x20, 0x40, 0x21, 0x20, 0x40, 0x40, 0x40, 0x40, 0x29, 0x63, 0x27, 0x27, 0x76, 0x78, 0x62, 0x6c]

for x in range(0,8):
  print(hex(sol[x] ^ sol[x+8]))
~~~

In the room ahead we get flying boots.
And that's it for this part of writeup :D 