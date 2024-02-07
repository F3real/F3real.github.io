Title: asm-some
Date: 2024-02-07 10:01
Modified: 2024-02-07 10:01
Category: reversing
Tags: asm, misc 
Slug: asm-some
Authors: F3real
Summary: Short google brainteaser 

On Munich BSides conference Google had this flyers with asm riddle.

~~~
It would be 'asm-some' to hear from you!
HINT: 32 bit
25 1c1f1c22 25 e3e0e3dd 2d 4e43422e 2d 37283c22 2d 1921411f 50
25 32322235 25 XXXXXXXX 2d 2c2f1b1b 2d 5c232129 2d 1380594c XX
25 2c2f1b1b 25 d3d0e4e4 XX 32322235 2d 22222422 2d 3d3c523c 50
25 XXXXXXXX 25 b1bcbdd1 2d 1c1f1c22 2d 25245424 2d 4c4c6252 50
~~~

We can, by just looking at the flyer, see some patterns and make some guesses.
For example in last column the missing value is probably `50`, similarly in 4th
column we can assume the missing value is `2d`. Also we can notice that 2nd and 6th column
are connected in some way, for example if in row A 2nd value is equal to 6th in row B then
2nd value of row B will be equal to 6th of row A.
 
Already using these guesses we can fill almost all of the missing fields but to get 
last one we need to understand what the values mean.

Following the hint and trying to decompile given hex string as 32 asm we get:

~~~asm
00000000 251C1F1C22                      AND EAX,221C1F1C
00000005 25E3E0E3DD                      AND EAX,DDE3E0E3
0000000A 2D4E43422E                      SUB EAX,2E42434E
0000000F 2D37283C22                      SUB EAX,223C2837
00000014 2D1921411F                      SUB EAX,1F412119
00000019 50                              PUSH EAX

0000001A 2532322235                      AND EAX,35223232
0000001F 2500000000                      AND EAX,????????             ; ??????
00000024 2D2C2F1B1B                      SUB EAX,1B1B2F2C
00000029 2D5C232129                      SUB EAX,2921235C
0000002E 2D13008059                      SUB EAX,4C598013
00000019 50                              PUSH EAX                     ;  0x50 our guess

00000034 252C2F1B1B                      AND EAX,1B1B2F2C
00000039 25D3D0E4E4                      AND EAX,E4E4D0D3             ;  0x2d our guess
0000003E 2D32322235                      SUB EAX,35223232
00000043 2D22222422                      SUB EAX,22242222
00000048 2D3D3C523C                      SUB EAX,3C523C3D
0000004D 50                              PUSH EAX

0000004E 254E43422E                      AND EAX,2E42434E              ; 0x4e43422e our guess
00000053 25B1BCBDD1                      AND EAX,D1BDBCB1
00000058 2D1C1F1C22                      SUB EAX,221C1F1C
0000005D 2D25245424                      SUB EAX,24542425
00000062 2D4C4C6252                      SUB EAX,52624C4C
00000067 50                              PUSH EAX
~~~

For this I used [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/), but any decompiler should be fine.
If we look at binary representation of values in `AND` instructions we see they always 
cancel each other giving 0 as result. Based on this we can confirm that our guess for
`0x4e43422e` was correct and that last missing value should be `0xcaddcdcd`.

Last thing remaining, is to figure out what does this asm snippet do.
We can emulate it in C:
~~~c
#include <stdio.h>
#include <stdint.h>

int main() {
    // Write C code here
    uint32_t EAX = 0;  // doesn't matter
    EAX &= 0x221C1F1C; // 00100010000111000001111100011100
    EAX &= 0xDDE3E0E3; // 11011101111000111110000011100011
    EAX -= 0x2E42434E;
    EAX -= 0x223C2837;
    EAX -= 0x1F412119;
    printf("0x%x\n", EAX);
 
    EAX &= 0x35223232; // 00110101001000100011001000110010
    EAX &= 0xCADDCDCD; // 11001010110111011100110111001101
    EAX -= 0x1B1B2F2C;
    EAX -= 0x2921235C;
    EAX -= 0x59800013;
    printf("0x%x\n", EAX);

	EAX &= 0x1B1B2F2C;  // 00011011000110110010111100101100
    EAX &= 0xE4E4D0D3;  // 11100100111001001101000011010011
    EAX -= 0x35223232;
    EAX -= 0x22242222;
    EAX -= 0x3C523C3D;
    printf("0x%x\n", EAX);

	EAX &= 0x2E42434E;  // 00101110010000100100001101001110
    EAX &= 0xD1BDBCB1;  // 11010001101111011011110010110001
    EAX -= 0x221C1F1C;
    EAX -= 0x24542425;
    EAX -= 0x52624C4C;
    printf("0x%x\n", EAX); 
    
    return 0;
}
~~~

If we run this program, we get:
~~~
0x90407362
0x6f6a2d65
0x6c676f6f
0x672d7073
~~~
and, taking in consideration endianess, this gives us solution:
`0x73702d676f6f676c652d6a6f62734090 -> sp-google-jobs@`