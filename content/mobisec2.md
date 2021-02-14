Title: MOBISEC CTF reversing 6-7
Date: 2019-4-9 10:01
Modified: 2019-4-9 10:01
Category: ctf
Tags: android, reversing, java, dex, apk
Slug: mobisec_ctf2
Authors: F3real
Summary: How to solve MOBISEC CTF reversing challenges 6-7

Let's look at the two harder challenges from MOBISEC ctf.
I'll host challenge apk files [here](https://github.com/F3real/ctf_solutions/tree/master/2019/mobisec) in case the site goes down. 

[TOC]

##Upos

Upos is probably most interesting challenge from this CTF. I felt like it was undervalued being only 30 points.

Description:
***Enjoy this Undebuggable Piece Of Software!***

So it's supposed to be undebuggable? Since it's reversing challenge we don't really care anyway if we can debug it.

###Anti-debug tricks
There are four different methods implemented to stop debugging. Interestingly main code for these checks is in `android.support.v7.app.Activity`. Same checks are also added to `checkFlag` function.

First check is detecting if frida is being used: 

Every Java application has a single instance of class `Runtime` that allows the application to interface with the environment in which the application is running. The current runtime can be obtained from the `getRuntime` method. 

~~~java
    //List running processes
    String cmd = "ls /proc"
    Runtime.getRuntime().exec(cmd).getInputStream();
~~~

Each row in `/proc/$PID/maps` describes a region of contiguous virtual memory in a process or thread. It contains pathname - If the region was mapped from a file, this is the name of the file. This field is blank for anonymous mapped regions.
  
~~~java
    //For every found process
    String cmd = "cat /proc/" + line + "/maps";
    Runtime.getRuntime().exec(cmd).getInputStream();
    //Check if string "frida" is found in result
    ...
~~~   
    
Second check performed is detecting if Google play store is installed on device:

~~~java
ctx.getPackageManager().getInstalledApplications(PackageManager.GET_META_DATA).iterator()
(((ApplicationInfo) it.next()).packageName.equals("com.android.vending"))
...
~~~

We also have check if debugger is connected:

~~~java
//null is used when invoking static methods
Class.forName("android.os.Debug").getMethod("isDebuggerConnected"), new Class[0]).invoke(null, new Object[0])).booleanValue();
~~~

And last check is if certificate is unchanged.
A package must be signed with at least one certificate which is at position zero. The package can be signed with additional certificates which appear as subsequent entries.

~~~java
InputStream input = new ByteArrayInputStream(packageInfo.signatures[0].toByteArray());
CertificateFactory cf = null;
try {
    cf = CertificateFactory.getInstance("X509");
} catch (CertificateException e3) {
    e3.printStackTrace();
}
X509Certificate c = null;
try {
    c = (X509Certificate) cf.generateCertificate(input);
} catch (CertificateException e4) {
    e4.printStackTrace();
}
String hexString = null;
try {
    hexString = convertToHex(MessageDigest.getInstance("SHA1").digest(c.getEncoded()));
} catch (NoSuchAlgorithmException e1) {
    e1.printStackTrace();
} catch (CertificateEncodingException e5) {
    e5.printStackTrace();
}
MainActivity.f25g4 = !hexString.equals("018a94a01edcfd1c8121f56dd36a412e62b3dd8b");
~~~

Now lets look at `checkFlag` function and this is where things get messy. Usually I used Jadx to decompile apks but it fails on this function.
So I decided to try Ghidra.

Well with Ghidra 9.0.1 we get some output but we also get a lot of warnings:
~~~text
/* WARNING: Removing unreachable block (ram,0x500253d8) */
~~~
A lot of code gets removed for supposedly being unreachable and generated Java doesn't even have single `return true`, obviously not good sign.

Now probably intended way is to try frida (maybe just rename binary since check performed is so simple) or some other instrumentation framework. But that would probably require setting android studio, frida, emulator and I am kinda lazy so let's try to find way around it.

If we look at CFG in Ghidra we can actually see full function, even parts that are deemed unreachable. If we select those parts of code they will actually decompile as undefined functions. Now this is step foward, but still variables are not connected to declarations in real `checkFlag` and for such large function this is problematic. 

So let's try to understand why Ghidra is thinking this part is unreachable
In decompiled code of check flag we have few `Exception` declarations:

~~~java
  ref_05 = new(IllformedLocaleException);
  uVar3 = ref_05.<init>();
  throwException(ref_05);
  return (boolean)uVar3;
~~~

Which seems really weird considering that these returns are never going to be hit (and btw Ghidra for now is not good at handling try/catch in Java). So we have to dive deeper, which in this case means we have to take looka at smali code.

###Smali
First lets look at few smali constructs:

try/catch:
~~~text
    :try_start_0
    [ some code inside try catch block]
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    [ some code code after try/catch block]

    :catch_0
    move-exception v1
    [some exception handling code]
~~~

There is also `catch_all` label usually used for finally blocks

Goto is not there in Java itself, but it exists at bytecode level and it can be used to obfuscate. Goto:

~~~text
    goto :label_1
    [... some code that will be skipped...]
    :label_1
    [... some code ...]
~~~

conditional

~~~text
    if-ne v0, v1, :cond_0    
    [... some code that will be executed if v0 and v1 are equal...]
    :cond_0
    [... some code that will be executed if v0 and v1 are not equal...]
~~~

To get smali from upos.apk we can use apktool:

~~~text
//extract apk to folder and convert classes.dex to smali files
apktool d upos
//compile smali files back to classes.dex and generates new apk in upos/dist/
apktool b upos/   
~~~

FC.smali is file containing `checkFlag` method:

If we find where error is generated in smali we have:

~~~text
    new-instance v10, Ljava/util/IllformedLocaleException;
    invoke-direct {v10}, Ljava/util/IllformedLocaleException;-><init>()V
    .end local v3    # "fs":[Z
    .end local v4    # "s":Lcom/mobisec/upos/Streamer;
    .end local v6    # "idx":I
    .end local p0    # "ctx":Landroid/content/Context;
    .end local p1    # "fl":Ljava/lang/String;
    throw v10
    :try_end_f
    .catch Ljava/util/IllformedLocaleException; {:try_start_f .. :try_end_f} :catch_9
    
    ....

    :catch_9
    move-exception v0
    move-object v5, v0
    move v10, v6
    goto/16 :goto_9
~~~

Which is basically obfuscated way just to jump to  `:goto_9`. We can just replace this code with:

~~~text
    .end local v3    # "fs":[Z
    .end local v4    # "s":Lcom/mobisec/upos/Streamer;
    .end local v6    # "idx":I
    .end local p0    # "ctx":Landroid/content/Context;
    .end local p1    # "fl":Ljava/lang/String;
    goto/16 :goto_9
    :try_end_f
    .catch Ljava/util/IllformedLocaleException; {:try_start_f .. :try_end_f} :catch_9
~~~

After rebuilding classes.dex with this changes Ghidra was able to connect previously unreachable blocks and we get proper output.

This trick is used on few other exceptions in `checkFlag` and we can just do same procedure for all of them:

~~~text
RejectedExecutionException
CertificateEncodingException
GeneralSecurityException
~~~

We just need to find places where we are sure exception is getting generated, find appropriate catch handler and then just patch out `throw` with appropriate `goto`. Same obfuscation is also done in `lm` function.

Now we can look at the `checkFlag` function in total [here](https://github.com/F3real/ctf_solutions/blob/master/2019/mobisec/upos/checkFlag.java).

It's 307 line function, but if we look carefully most of the code are just red herrings made to slow us down. Real check is just from line 260 to the end (and also we have to count *exact* number of `streamer.step()` calls).

Since code is large I'll just write a simplified pseudo code of check:

~~~
    flag8 = flag.substring(8)
    while i < 30:
        ref = char(i) + char(i+1)
        do_some_streamer_steps()
        x = streamer.g2()
        y = streamer.g2()
        l = convert_to_num(shifts_letter_a_bit(ref))
        if l = m[x][y]:
            bool_array[i] = True
        i = i + 1
    hash = flag(hash)
    if hash == true_flag_hash
        return true
~~~

`m` is actually array loaded from `lotto.dat` asset. 

We can just copy this part of flag check and create local version used to find flag. Numerical value generated by two letter combination is unique, this means we can just generate all of them, calculate resulting values and compare them to values asked in flag check to get flag.

I've also added solver in Java to repo with upos.apk.

Flag:
`MOBISEC{Isnt_this_a_truly_evil_undebuggable_piece_of_sh^W_software??}`


##Loadme

This is kinda expected challenge and it's about `DexClassLoader`.

We have apk calling server, getting new apk form it, loading it and calling `load` method from new apk.
This new apk will load `logo.png` from first apk, decrypt it (just xor), load that apk and call `checkFlag` from it.

There are few encrypted strings we have to get around it but since keys and methods to decrypt are in apk itself it's not a big problem.

`context.getPackageName()` used in some decryptions is actually same as APPLICATION_ID from BuildConfig.

If we use Jadx to decompile 3rd apk we get flag in plain text.

Flag:
`MOBISEC{dynamic_code_loading_can_make_everything_tricky_eh?}`