Title: Pragyan CTF 2019 Super Secure Vault
Date: 2019-3-12 10:01
Modified: 2019-3-12 10:01
Category: ctf
Tags: ctf, reversing
Slug: pragyan_supersecurevault
Authors: F3real
Summary: How to solve Pragyan CTF 2019 Super Secure Vault reversing challenge

Super secure vault was one harder challenges from Pragyan CTF and also one bringing most points. [Here](https://github.com/F3real/ctf_solutions/tree/master/2019/pragyan/SuperSecureVault) you can find full solution and binary if you want to follow along.

We need to reverse the program, find correct input and get the flag.

First, let's look at the source code in IDA:

~~~c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ....
  v13 = 213;
  v14 = 8;
  v15 = 229;
  v16 = 5;
  v17 = 25;
  v18 = 4;
  v19 = 83;
  v20 = 7;
  v21 = 135;
  v22 = 5;
 printf("Enter the key: ", argv, envp);
  __isoc99_scanf("%s", &s);
  if ( strlen(&s) > 30 )
    fail(0LL);
  v3 = getNum((__int64)"27644437104591489104652716127", 0, v14);// 27644437
  if ( mod(&s, v3) != v13 )
    fail(0LL);
  v10 = v14;
  v4 = getNum((__int64)"27644437104591489104652716127", v14, v16);// 10459
  if ( mod(&s, v4) != v15 )
    fail(0LL);
  v11 = v16 + v10;                              // 13
  v5 = getNum((__int64)"27644437104591489104652716127", v11, v18);// 1489
  if ( mod(&s, v5) != v17 )
    fail(0LL);
  v12 = v18 + v11;                              // 17
  v6 = getNum((__int64)"27644437104591489104652716127", v12, v20);// 1046527
  if ( mod(&s, v6) != v19 )
    fail(0LL);
  v7 = (unsigned int)getNum((__int64)"27644437104591489104652716127", v20 + v12, v22);// 16127
  if ( mod(&s, v7) != v21 )
    fail(0LL);
  printf("Enter password: ", v7);
  __isoc99_scanf("%s", &s2);
  func2((__int64)&s2, &s, "27644437104591489104652716127");
  result = 0;
  ...
}
~~~

Program asks us for a key, after which it checks results of modulo operations on it. Modulo values are obtained from `getNum` function.

~~~c
__int64 __fastcall getNum(__int64 numString, int start, int offset)
{
  int x; // [sp+18h] [bp-8h]@1
  int i; // [sp+1Ch] [bp-4h]@1

  x = 0;
  for ( i = start; i < start + offset; ++i )
    x = 10 * x + *(_BYTE *)(i + numString) - 48;
  return (unsigned int)x;
}
~~~

Actually, this is rather simple functions converting a portion of the input string, from start to offset, to number.

Looking at the code we see that in total we have 5 different conditions that have to hold for our input:

~~~text
s = 213 mod 27644437
s = 229 mod 10459
s = 25 mod 1489
s = 83 mod 1046527
s = 135 mod 16127
~~~

Since modulus are coprime, we can use chinese reminder theorem to solve this system of equations. I won't go into details of it, but the good explanation can be found [here](http://homepages.math.uic.edu/~leon/mcs425-s08/handouts/chinese_remainder.pdf).

Python solution:

~~~python
a  = [213, 229, 25, 83, 135]
m  = [27644437, 10459, 1489, 1046527, 16127]


#Check if all numbers are coprime
for i in range(0, len(m)):
    for j in range(i + 1, len(m)):
        if gcd(m[i], m[j]) != 1:
            print("Numbers are not coprime.")
            quit()

#Calculate solution            
M = reduce(mul, m, 1)
zi = [M//x for x in m];
yi = [modinv(x,y) for x,y in zip(zi,m)]  
wi = [x*y%M for x,y in zip(zi,yi)]
solution = [x*y for x,y in zip(wi,a)]
solution = sum(solution) % M

print(f"Solution: {solution}")
~~~

Running our code we get 3087629750608333480917556.

Now we also have to figure the second part. Let's look at the source code of the second function:

~~~c
int __fastcall func2(__int64 s2, char *s1, const char *numString)
{
  unsigned __int64 v3; // rax@1
  int v4; // ST30_4@7
  int v5; // ST34_4@7
  int i; // [sp+24h] [bp-3Ch]@1
  int v8; // [sp+28h] [bp-38h]@1
  int v9; // [sp+28h] [bp-38h]@6
  int v10; // [sp+2Ch] [bp-34h]@1
  int v11; // [sp+2Ch] [bp-34h]@6
  char *v12; // [sp+40h] [bp-20h]@1

  v12 = strcat(s1, numString);
  v3 = (unsigned __int64)&v12[strlen(v12)];
  *(_WORD *)v3 = '08';
  *(_BYTE *)(v3 + 2) = '\0';
  i = 0;
  v8 = 0;
  v10 = strlen(v12) >> 1;
  while ( v8 < strlen(v12) >> 1 )
  {
    if ( *(_BYTE *)(i + s2) != matrix[100 * (10 * (v12[v8] - 48) + v12[v8 + 1] - 48) - 48 
                               + 10 * (v12[v10] - 48)
                               + v12[v10 + 1]])
      fail(1LL);
    ++i;
    v8 += 2;
    v10 += 2;
  }
  v9 = 0;
  v11 = strlen(v12) >> 1;
  while ( v9 < strlen(v12) >> 1 )
  {
    v4 = 10 * (v12[v9] - 48) + v12[v9 + 1] - 48;
    v5 = 10 * (v12[v11] - 48) + v12[v11 + 1] - 48;
    if ( *(_BYTE *)(i + s2) != matrix[100 * (v4 * v4 % 97) + v5 * v5 % 97] )
      fail(1LL);
    ++i;
    v9 += 2;
    v11 += 2;
  }
  puts("Your Skills are really great. Flag is:");
  return printf("pctf{%s}\n", s2);
}
~~~

Our first input is concatenated with string constant `numString` and later expanded with `80`. This string is used with hardcoded `matrix` to check the second input we provided.

We can export `matrix` array from IDA by going `Edit->Export data`. Since we have both first input and `matrix` we can just write the same code to output what should `s2` string be. The easiest way to do this is just to make a copy C code we have and modify it.

Python solver:

~~~python
v12 = "30876297506083334809175562764443710459148910465271612780"

print(f"v12 len: {len(v12)}")

i = 0
v8 = 0
v10 = len(v12) // 2

password = ""

#Checks first part of function
while v8 < len(v12)/2:

    index = 100 * (10 * (ord(v12[v8]) - 48) + ord(v12[v8 + 1]) - 48) - 48 + 10 * ( ord(v12[v10]) - 48) + ord(v12[v10 + 1])
    
    password = password + chr(matrix[index])

    i+=1;
    v8 += 2
    v10 += 2

v9 = 0
v11 = len(v12) // 2

while v9 < len(v12) // 2:
    v4 = 10 * (ord(v12[v9]) - 48) + ord(v12[v9 + 1]) - 48
    v5 = 10 * (ord(v12[v11]) - 48) + ord(v12[v11 + 1]) - 48
    
    password = password + chr(matrix[100 * (v4 * v4 % 97) + v5 * v5 % 97])

    i+=1;
    v9 += 2;
    v11 += 2;

print(password)
~~~

Running our code we get: `R3v3rS1Ng_#s_h311_L0t_Of_Fun`