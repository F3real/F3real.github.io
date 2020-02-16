Title: W3challs striptease
Date: 2020-2-16 10:02
Modified: 2020-2-16 10:02
Category: reversing
Tags: crackme, elf
Slug: w3challs_striptease
Authors: F3real
Summary: Solution to W3challs striptease challenge


In this post, we will take a quick look at one of the simpler reversing challenges from W3challs, striptease.

If we open it in `radare2` and look at the entry function we see:

~~~text
 0x08048075      be00000000     mov esi, 0
│           ; CODE XREF from fcn.08048075 @ +0x46
│       ┌─> 0x0804807a      8b1dd0900408   mov ebx, dword [segment.LOAD1] ; [0x80490d0:4]=188
│       ╎   0x08048080      83c303         add ebx, 3
│       ╎   0x08048083      391dd4900408   cmp dword [0x80490d4], ebx  ; [0x80490d4:4]=255
│      ┌──< 0x08048089      7d06           jge 0x8048091
│      │╎   0x0804808b      2b1dd4900408   sub ebx, dword [0x80490d4]  ; [0x80490d4:4]=255
│      │╎   ; CODE XREF from fcn.08048075 @ 0x8048089
│      └──> 0x08048091      b899800408     mov eax, 0x8048099
└       ╎   0x08048096      ffe0           jmp eax
        ╎   0x08048098      83891dd09004.  or dword [ecx + 0x490d01d], 8
        ╎   0x0804809f      bf5a910408     mov edi, 0x804915a
        ╎   0x080480a4      8b0435d89004.  mov eax, dword [esi + 0x80490d8]
        ╎   0x080480ab      31d8           xor eax, ebx
        ╎   0x080480ad      890435d89004.  mov dword [esi + 0x80490d8], eax
        ╎   0x080480b4      46             inc esi
        ╎   0x080480b5      81fe81000000   cmp esi, 0x81               ; 129
        └─< 0x080480bb      75bd           jne 0x804807a               ; fcn.08048075+0x5
        ┌─< 0x080480bd      e916100000     jmp 0x80490d8
        │   0x080480c2      b801000000     mov eax, 1
        │   0x080480c7      bb00000000     mov ebx, 0
        │   0x080480cc      cd80           int 0x80
~~~

This is the only function in binary that we can immediately inspect, so we need to find what does it do. If we look closely, we see that it is a simple loop performing XOR decryption with incrementing key. After loop finishes, control will jump to decrypted code. We can dynamically debug binary and see the decrypted code or we can write a simple python script to do it for us. 

The flag is a hardcoded string in part of code that gets decrypted.

Solution:

~~~python
TARGET_BYTE_OFFSET = 0xd8
REPETITIONS = 0x81  # 129
INCREMENT = 3
TARGET_BIN = 'striptease-1be7d788d5e8de3ea92166b9d9fdbd5ce62d97e76136675c3ef12ef7b3db3602'
TARGET_BIN_MODIFIED = 'striptease-modified'

# load encrypted part of binary:
with open(TARGET_BIN, 'rb') as target:
    target.seek(TARGET_BYTE_OFFSET)
    encrypted_instructions = bytearray(target.read(REPETITIONS))

    print(f'Length of encrypted part of binary: {len(encrypted_instructions)}')
    # decode instructions
    esi = 0
    ebx = 0xbc
    while esi != REPETITIONS:
        ebx = ebx + INCREMENT
        if ebx >= 255:
            ebx -= 255
        encrypted_instructions[esi] ^= ebx
        esi += 1
    with open(TARGET_BIN_MODIFIED, 'wb') as res:
        res.write(encrypted_instructions)
~~~