Title: Uphigh CTF lvl. 4
Date: 2018-7-23 10:01
Modified: 2018-7-23 10:01
Category: ctf
Tags: ctf, crypto
Slug: uphigh_lvl4
Authors: F3real
Summary: How to solve Uphigh CTF lvl. 4

This is fourth level of CTF found at 
[http://uphigh.com.au/4/](http://uphigh.com.au/4/)

In this challenge we have simple website asking as for background color code.

![challenge start screen]({static}/images/2018_8_23_Vonex.png){: .img-fluid .centerimage}

Looking at the page source code we don’t see much:
~~~html
</div><form id="form" action="/4/" method="post">
	Background colour: <input type="text" name="bgcolour" value='#ffffff'><button id="submit" type="submit">Go</button>
</form>
<br>
<div id='text'><!-- key -->Vonex is hiring</div><style>#resume {margin-left: 38%; margin-top:7%;}</style> 
~~~

Trying to inject commands instead of color, gives us no results but looking at network requests/responses we see interesting cookie:
```
V0n3XL7d=011101010000111000001010000000110001100101000011000011010101000001000001000011000000111100010011000010100000101001000100;
```
Now looking at the html source and at the cookie value, could it be some sort of Vigenère cipher ?

~~~python
import binascii
cookie = b"011101010000111000001010000000110001100101000011000011010101000001000001000011000000111100010011000010100000101001000100"
comment = b"Vonex is hiring"

cookie_hex = hex(int(cookie,2))
print("Cookie in hex:  " + cookie_hex)

comment_hex = "0x"+ str(binascii.hexlify(comment))[2:-1]
print("Comment in hex: " + comment_hex)

res_hex = hex(int(comment_hex, 16) ^ int(cookie_hex, 16))
print("Result hex:     " + res_hex)

res_ascii = str(binascii.unhexlify(res_hex[2:]))[2:-1]
print("Result:         " + res_ascii)
~~~

As result we get:
```
Cookie in hex:  0x750e0a0319430d50410c0f130a0a44
Comment in hex: 0x566f6e657820697320686972696e67
Result hex:     0x236164666163642361646661636423
Result:         #adfacd#adfacd#
```
Trying result we obtained as color gives us our flag :D

![solved challenge screen]({static}/images/2018_8_23_VonexResult.png){: .img-fluid .centerimage}
