Title: UTCTF 2019 Super Secure Authentication
Date: 2019-3-19 10:01
Modified: 2019-3-19 10:01
Category: ctf
Tags: ctf, reversing, java
Slug: utctf_supersecureauthentication
Authors: F3real
Summary: How to solve UTCTF 2019 Super Secure Authentication reversing challenge

This time we are given zip file containing few different, suspiciously large, compiled classes. If you want to follow along, files can be downloaded [here](https://github.com/F3real/ctf_solutions/tree/master/2019/utctf/SuperSecureAuthentication).

~~~text
       Length  Name
       ---     ---
       1999    Authenticator.class
       4097    jBaseZ85.class
       3152661 Verifier0.class
       3151489 Verifier1.class
       3335819 Verifier2.class
       3210206 Verifier3.class
       3151489 Verifier4.class
       3638156 Verifier5.class
       3382336 Verifier6.class
       3068109 Verifier7.class
~~~

We can run a given program with `java Authenticator <password>` from cmd.

Looking at the source of the `Authenticator` in Ghidra we see that there is `checkFlag` function.

~~~java
  objectRef = param1.substring(0,7);
  bVar3 = objectRef.equals("utflag{");
  if (bVar3 == false) {
    return false;
  }
  objectRef = param1;
  iVar1 = param1.length();
  cVar2 = objectRef.charAt(iVar1 + -1);
  if (cVar2 != '}') {
    return false;
  }
  objectRef_01 = new(StringTokenizer);
  iVar4 = 7;
  objectRef_00 = objectRef_01;
  iVar1 = param1.length();
  objectRef = param1.substring(iVar4,iVar1 + -1);
  objectRef_01.<init>(objectRef,"_");
  objectRef = objectRef_00.nextToken();
  bVar3 = Verifier0.verifyFlag(objectRef);
  if (bVar3 == false) {
    return false;
  }
  ...
~~~

It checks if our passed string starts with `utflag{` and ends with `}`. The rest of input is split on `_` and passed to different Verifier classes.
So our flag has the format of `utflag{x_x_x_x_x_x_x}` and each Verifier is tasked with checking one part.

Looking at the source code of `Verifer0` we can't see much. It dynamically loads the new class from hardcoded array and calls `verifyFlag` function it provides.

~~~java
  ....
  objectRef_02 = new Verifier0();
  objectRef = objectRef_02.defineClass("Verifier0",Verifier0.arr,0,Verifier0.arr.length);
  ppCVar1 = new Class[1];
  ppCVar1[0] = String.class;
  objectRef_00 = objectRef.getMethod("verifyFlag",ppCVar1);
  ppOVar2 = new Object[1];
  ppOVar2[0] = param1;
  objectRef_01 = objectRef_00.invoke(null,ppOVar2);
~~~

To make matters a bit harder, `arr0` is encoded in Z85 (a format for representing binary data as printable text).

After saving the first dynamically loaded class and decompiling it, we get almost identical code as with the original class. This led me to assume that classes are probably nested in a manner similar to matryoshka dolls and that we need to automate this process.

First, we can see which version of java is used to compile these class files.
For this, we are going to use `javap` disassembler which is part of JDK.

~~~text
javap -v .\Authenticator.class | findstr "major"
  major version: 52
~~~

Major version 52 corresponds to java 8. We can use the same procedure to view the minor version as well.

To dynamically load classes and access fields we are going to use java reflection. Since we can write the solution in the same folder as extracted classes we don't have to worry about imports. 

Solution code should be pretty understandable:

~~~java
import java.lang.reflect.Field;
import java.lang.NoSuchFieldException;
import java.io.FileOutputStream;

//class ClassLoader is an abstract class so we have to extend it, if we want to use it.
public class Sol extends ClassLoader{

    public static void main(String[] args) throws Exception{
        for (int i = 0; i < 8; i++) {
            
            int currentVer = 0;
            String name = "Verifier" + String.valueOf(i);
            
            Class classT = Class.forName(name);
            Object ver = classT.newInstance();
            
            while (true) {
                Field f;
                try {
                    //arr field is private so we have to change access permission
                    f = ver.getClass().getDeclaredField("arr");
                    f.setAccessible(true);
                }
                catch(NoSuchFieldException e) {
                    break;
                }
                byte [] arr =  (byte []) f.get(ver);
                
                try (FileOutputStream fos = new FileOutputStream(name + String.valueOf(currentVer) + ".class")) {
                    fos.write(arr);
                }
                
                /* We have to recreate class loader every time to avoid
                java.lang.LinkageError: loader (instance of  Sol): attempted  duplicate class definition
                */
                Sol _classLoader = new Sol();
                Class loadedClass  = _classLoader.defineClass(name, arr,0, arr.length);
                ver = loadedClass.newInstance();
                currentVer += 1;
            }
        }
    }

}
~~~

We can compile our solution with `javac`.

After running our program we see that each verifier had 28 nested classes. 
Almost all of the final classes also implement some simpler form of encryption.

Looking at decompiled source of last class from `Verifier0` we see that it just uses XOR, which is easily reversible.

~~~python
x = [ 0x32, 0x30, 0x2d, 0x32, 0x2a, 0x27, 0x36, 0x31]
y = [ xx ^ 0x42 for xx in x]
>>> ''.join(chr(xx) for xx in y)
'prophets'
>>>
~~~

`Verifier1` just checks string in reverse order:

~~~python
x = [0x73, 0x75, 0x6f, 0x69, 0x78, 0x6e, 0x61]
x.reverse()
>>> "".join(chr(i) for i in x)
'anxious'
~~~

`Verifier2` appends to each flag char string `"foo"` and hashes it with java `hashCode` function. Since we have saved hashes we can just hash all lowercase ascii characters and get our flag.

~~~python
import string

def java_string_hashcode(s):
  h = 0
  for c in s:
    h = (31 * h + ord(c)) & 0xFFFFFFFF
  return ((h + 0x80000000) & 0xFFFFFFFF) - 0x80000000

x = [0x2f01e2, 0x2f7641, 0x331939, 0x3401f7, 0x32a4da, 0x3147bd, 0x3647d2,0x3147bd, 0x3401f7, 0x338d98]
sol = {}
for ch in string.ascii_lowercase:
  hashcode = java_string_hashcode(ch + "foo")
  if hashcode in x:
    sol[hashcode] = ch

for i in x:
  print(sol[i])
>>> demolition
~~~

`Verifier3` does simple math operations on encrypted string:

~~~python
x =  "obwaohfcbwq"
x1 = [ (ord(i) - 0x55) % 0x1a for i in x]
x2 = [ i + 0x61 for i in x1]
>>> "".join(chr(i) for i in x2)
'animatronic'
~~~

`Verifier4` is also similar.

~~~python
x = [0xd30, 0xcdf, 0xe3e, 0xc73, 0xd9c, 0xcc4]
x1 = [ i - 0x238 for i in x]
x2 = [ i // 0x1b for i in x1]
>>>"".join(chr(i) for i in x2)
'herald'
~~~

`Verifier5` hashes every char of input with MD5, concatenates them and compares them do hardcoded string.

~~~python
import hashlib
import string
x = "8FA14CDD754F91CC6554C9E71929CCE7865C0C0B4AB0E063E5CAA3387C1A8741FBADE9E36A3F36D3D676C1B808451DD7FBADE9E36A3F36D3D676C1B808451DD7".lower()
while x != "":
  for ch in string.ascii_lowercase:
    m = hashlib.md5()
    m.update(ch.encode()) #UTF-8 by default
    currentDigest = m.digest().hex()
    if x.startswith(currentDigest):
      print(ch + "    " + currentDigest)
      x = x.replace(currentDigest, "", 1)
>>>
f    8fa14cdd754f91cc6554c9e71929cce7
i    865c0c0b4ab0e063e5caa3387c1a8741
z    fbade9e36a3f36d3d676c1b808451dd7
z    fbade9e36a3f36d3d676c1b808451dd7
~~~

`Verifier6` uses SHA1 to hash input string and compare it with hardcoded hash value `1B480158E1F30E0B6CEE7813E9ECF094BD6B3745`. We can quickly find a solution by just googling it. The solution is the string `stop`.

`Verifier7` just checks if provided string equals to `goodbye`.

Combining all of this we get our flag:
`utflag{prophets_anxious_demolition_animatronic_herald_fizz_stop_goodbye}`