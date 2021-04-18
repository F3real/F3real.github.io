Title: SHA 2017 Title case
Date: 2021-4-17 10:01
Modified: 2021-4-17 10:01
Category: ctf
Tags: python
Slug: sha_2017_title_case
Authors: F3real
Summary: SHA 2017 Title Case solution

I found this challenge in the Computest CTF, but it turns to be reused challenge from older SHA 2017 CTF.

The challenge itself is pretty simple:

~~~python
#!/usr/bin/env python
eval(raw_input().title())
~~~

It is actually a bit of trivia challenge, requiring knowledge of Python 2.7 encodings. In Python source files it is possible to specify encoding using comment (1st or 2nd line in program). In this case encoding interesting to us is `unicode_escape`, which is defined as ([PEP-0100](https://www.python.org/dev/peps/pep-0100/)):

* all non-escape characters represent themselves as Unicode ordinal (e.g. 'a' -> U+0061).
* all existing defined Python escape sequences are interpreted as Unicode ordinals; note that \xXXXX can represent all Unicode ordinals, and \OOO (octal) can represent Unicode ordinals up to U+01FF.
* a new escape sequence, \uXXXX, represents U+XXXX; it is a syntax error to have fewer than 4 digits after \u.

Purpose of this encoding is to produce a string that is suitable as Unicode literal in Python source code.

Let's look at example (Python 2.7):

~~~python
#coding:unicode_escape
print \154en('test')
~~~

The \154 is octal escape sequence that will be interpreted as Unicode ordinal 'l'.

The comment specifying encoding is usually written as:

~~~text
# -*- coding: <encoding-name> -*-
~~~

but as seen in previous example it is actually much more flexible as Python uses following regex for it([PEP-0263](https://www.python.org/dev/peps/pep-0263/)):

~~~text
^[ \t\v]*#.*?coding[:=][ \t]*([-_.a-zA-Z0-9]+)
~~~

The unicode escape sequences are unaffected by .title() function.

~~~python
s2 = r'\154en("test")'
print(s2.title())
#output \154En("test")
~~~
We see that 'e' got changed but that octal escape sequence for 'l' remained same, so to bypass the .title() function we just need to unicode escape whole command we want to execute. We can use following Python function:

~~~python
def unicode_escape(s):
	return "".join(['\\' + oct(ord(letter)).lstrip("o0").zfill(3) for letter in s])
~~~

Last thing remaining is to use less known option of raw_input and give it encoding comment as input.

~~~python
# here we add random letter (int this case `c`) before `coding` as regex is case-sensitive
# and first letter will get changed to upercase by .title()
payload = "#ccoding:unicode_escape\n" + unicode_escape('len("AAA")')

print eval(payload.title())
~~~

With this we can simply execute any command we want making challenge trivial.
Note: this approach is not usable in Python 3.

