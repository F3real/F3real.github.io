Title: ACE labs puzzle
Date: 2021-8-21 10:01
Modified: 2021-8-21 10:01
Category: ctf
Tags: assembly
Slug: ace_labs_puzzle
Authors: F3real
Summary: ACE labs assembly puzzle

Let's take a look at short assembly puzzle from the ACE labs.
~~~asm
  AND       eax, 0                    
  CALL      $ + 0xA                
  ENTER     0, 0
 
  LAHF 
  ADD       eax, 0xC829
  BSWAP     eax
  SHR       eax, 0x13 
~~~
Besides this snippet there is just a textbox were we can enter our answer.

Just looking at intructions we see that some of them are going to be skipped due to `CALL`. The `$` is NASM evaluates to the assembly position of the line containing it. In our case this means we are going to jump 10 bytes from current address.
We can compile this snippet using `nasm`.

~~~text
nasm -felf64 snippet.asm
~~~

And decompile it using `objdump` 
~~~text 
objdump -dw -Mintel <output>
~~~

to see hex representation of assembly. 

~~~text
  0000000000000000 <.text>:
   0:	83 e0 00             	and    eax,0x0
   3:	e8 05 00 00 00       	call   0xd
   8:	c8 00 00 00          	enter  0x0,0x0
   c:	9f                   	lahf   
   d:	05 29 c8 00 00       	add    eax,0xc829
  12:	0f c8                	bswap  eax
  14:	c1 e8 13             	shr    eax,0x13
~~~

Jumping 10 bytes gets us to the `ADD` instruction. Since `EAX` is zeroed out at the start with `AND` instruction, this will just put 0xC829 in it. Bitswapped this becomes 0x29c80000 (since we have 32bit register), and once we shift right by 0x13 we get 0x539.
In decimal this is 1337, which is also the answer to the puzzle.

~~~python
print(hex(0x29c80000 >> 0x13))
0x539
~~~

We can also just link the file we got from `nasm` and debug it.
~~~text
ld <nasm_output> -o <output_name>
gdb <output_name>
~~~
In `gdb` we can put breakpoint at first instruction using `starti` and continue stepping one instruction at a time using `si` until we reach end of the snippet. If we look at value in rax register at the end we will see same value 1337 (`layout reg` enables register view in `gdb`).

![Debugger view]({static}/images/2021_8_21_debugger.png){: .img-fluid .centerimage}