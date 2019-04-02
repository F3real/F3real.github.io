Title: MOBISEC CTF reversing 1-5
Date: 2019-4-3 10:01
Modified: 2019-4-3 10:01
Category: ctf
Tags: android, reversing, java, dex, apk
Slug: mobisec_ctf1
Authors: F3real
Summary: How to solve MOBISEC CTF reversing challenges 1-5

MOBISC CTF offers few different Android reversing challenges, it can be found [here](https://challs.reyammer.io/).

To reverse Android apk files, we can use few different tools:

* Jadx
* dex2jar and JD-GUI
* Ghidra

For most of this challenges I'll be using Jadx. It's really simple to use and works great (I suggest latest unstable version). Sometimes decompilation of methods fail, but in that case Ghidra will usually be able to help.

I'll host challenge apk files [here](https://github.com/F3real/ctf_solutions/tree/master/2019/mobisec) in case the site goes down. 

Challenges:

[TOC]

##Babyrev

Apk are basically zip files containing all required assets for application. Java (or Kotlin) code is compiled to Dalvik bytecode instead of regular JVM bytcode and contained in `classes.dex` files.

To find start activity and other general information about app, we can look in `Resources\AndroindManifest.xml`.

~~~xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="28" android:compileSdkVersionCodename="9" package="com.mobisec.babyrev" platformBuildVersionCode="28" platformBuildVersionName="9">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="28"/>
    <application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="android.support.v4.app.CoreComponentFactory">
        <activity android:name="com.mobisec.babyrev.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
~~~

If we look at decompiled source code of `com.mobisec.babyrev.MainActivity` we see that it just calls `FlagChecker.checkFlag` function on input we provide.

In `FlagChecker` class main check is:

~~~java
if (
!flag.startsWith("MOBISEC{") ||
new StringBuilder(flag).reverse().toString().charAt(0) != '}' ||
flag.length() != 35 ||
!flag.toLowerCase().substring(8).startsWith("this_is_") ||
!new StringBuilder(flag).reverse().toString().toLowerCase().substring(1).startsWith(ctx.getString(R.string.last_part)) ||
flag.charAt(17) != '_' ||
flag.charAt((int) (((double) getY()) * Math.pow((double) getX(), (double) getY()))) != flag.charAt(((int) Math.pow(Math.pow(2.0d, 2.0d), 2.0d)) + 1) ||
!bam(flag.toUpperCase().substring((getY() * getX()) * getY(), (int) (Math.pow((double) getZ(), (double) getX()) - 1.0d))).equals("ERNYYL") ||
flag.toLowerCase().charAt(16) != 'a' ||
flag.charAt(16) != flag.charAt(26) ||
flag.toUpperCase().charAt(25) != flag.toUpperCase().charAt(26) + 1) {
   ... 
}
~~~

Rather complicated looking, but if we go through it we can significantly simplify it.

Function `getX()`, `getY()` and `getZ()` return constant values and can be optimized out and `bam` function is actually just rot13 cipher.

`ctx.getString(R.string.last_part)` returns string value from compiled resources (`resources.arsc` file)  which is kinda just key value store. In Jadx we can find string value under `/resources.arsc/res/values/strings.xml`.

Much more readable check from which we can easily find solution:

~~~java
if (
!flag.startsWith("MOBISEC{") ||
new StringBuilder(flag).reverse().toString().charAt(0) != '}' ||
flag.length() != 35 ||
!flag.substring(8).startsWith("this_is_") ||
!new StringBuilder(flag).reverse().toString().substring(1).startsWith("ver_cis")) ||
flag.charAt(16) != 'a' ||
flag.charAt(17) != '_' ||
flag.charAt(24) != '_' ||
flag.charAt(26) != 'a' ||
!bam(flag.substring(18, 24)).equals("ERNYYL") ||
flag.charAt(25) != flag.charAt(26) + 1) {
    ...
}
~~~

After this we also have simple regex that checks if characters are alternating between lowercase and uppercase.

Putting it all together we get our flag: `MOBISEC{ThIs_iS_A_ReAlLy_bAsIc_rEv}`

##Pincode

This time flag is not directly contained in apk we are reversing. In `MainActivity` we have:

~~~java
    if (PinChecker.checkPin(MainActivity.this, pin)) {
        try {
            flag = MainActivity.this.getFlag(pin);
        } catch (Exception e) {
            exception = e.getMessage();
        }
~~~

So basically if pin we enter passes check, app will contact server (`getFlag` function) and show us the real flag.

Code for pin check is:

~~~java
    public static boolean checkPin(Context ctx, String pin) {
        if (pin.length() != 6) {
            return false;
        }
        try {
            byte[] pinBytes = pin.getBytes();
            for (int i = 0; i < 25; i++) {
                for (int j = 0; j < 400; j++) {
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    md.update(pinBytes);
                    pinBytes = (byte[]) md.digest().clone();
                }
            }
            if (toHexString(pinBytes).equals("d04988522ddfed3133cc24fb6924eae9")) {
                return true;
            }
            return false;
        } catch (Exception e) {
            Log.e("MOBISEC", "Exception while checking pin");
            return false;
        }
    }
~~~

So basically, we have 6 digit pin which gets hashed 10000 (400*25) times using md5 and compared to `d04988522ddfed3133cc24fb6924eae9`. 

With no other smarter solution on mind, I decided to brute force it using Python:

~~~python
import hashlib
import itertools

#iterates over all 6 digit combinations
for combination in itertools.product(range(10), repeat=6):
    pin = ''.join(str(x) for x in combination).encode()
    for i in range(0, 25 * 400):
        m = hashlib.md5()
        m.update(pin)
        pin = m.digest()

    if pin.hex() == "d04988522ddfed3133cc24fb6924eae9":
        print(''.join(str(x) for x in combination))
        break;
~~~

If we leave our script running for a while (like few hours) we get correct pin `703958`. Contacting server using `https://challs.reyammer.io/pincode/703958` we get out flag: `MOBISEC{local_checks_can_be_very_bad_for_security}`

##Gnirts

This time things get much more messy. Let's look at the source code of check flag (I've added some comments to explain key parts):

~~~java

    public static boolean checkFlag(Context ctx, String flag) {
        if (!flag.startsWith("MOBISEC{") || !flag.endsWith("}")) {
            return false;
        }
        String core = flag.substring(8, 40);
        if (core.length() != 32) {
            return false;
        }
        //foo() runs base64 decode on hardcoded string 10 times
        //final result is just '-'
        String[] ps = core.split(foo());
        if (ps.length != 5 || !bim(ps[0]) || !bum(ps[2]) || !bam(ps[4]) || !core.replaceAll("[A-Z]", "X").replaceAll("[a-z]", "x").replaceAll("[0-9]", " ").matches("[A-Za-z0-9]+.       .[A-Za-z0-9]+.[Xx ]+.[A-Za-z0-9 ]+")) {
            return false;
        }
        //This parts just checks if chars at idxs positions are same
        char[] syms = new char[4];
        int[] idxs = new int[]{13, 21, 27, 32};
        Set<Character> chars = new HashSet();
        for (int i = 0; i < syms.length; i++) {
            syms[i] = flag.charAt(idxs[i]);
            chars.add(Character.valueOf(syms[i]));
        }
        int sum = 0;
        for (char c : syms) {
            sum += c;
        }
        //Main part of check
        if (sum == 180 && chars.size() == 1 && 
        m2me(ctx, m0dh(m1gs(ctx.getString(C0055R.string.ct1), ctx.getString(C0055R.string.f2k1)), ps[0]), ctx.getString(C0055R.string.f9t1)) && 
        m2me(ctx, m0dh(m1gs(ctx.getString(C0055R.string.ct2), ctx.getString(C0055R.string.f3k2)), ps[1]), ctx.getString(C0055R.string.f10t2)) && 
        m2me(ctx, m0dh(m1gs(ctx.getString(C0055R.string.ct3), ctx.getString(C0055R.string.f4k3)), ps[2]), ctx.getString(C0055R.string.f11t3)) && 
        m2me(ctx, m0dh(m1gs(ctx.getString(C0055R.string.ct4), ctx.getString(C0055R.string.f5k4)), ps[3]), ctx.getString(C0055R.string.f12t4)) && 
        m2me(ctx, m0dh(m1gs(ctx.getString(C0055R.string.ct5), ctx.getString(C0055R.string.f6k5)), ps[4]), ctx.getString(C0055R.string.f13t5)) && 
        m2me(ctx, m0dh(m1gs(ctx.getString(C0055R.string.ct6), ctx.getString(C0055R.string.f7k6)), flag), ctx.getString(C0055R.string.f14t6))) {
            return true;
        }
        return false;
    }
~~~

Let's try to simplify one of main check parts:

~~~java
//One part of the flag check, other 4 are identical and just use different input
//ps[0] is just 1st part of our flag split on "-"
m2me(ctx, m0dh(m1gs(ctx.getString(C0055R.string.ct1), ctx.getString(C0055R.string.f2k1)), ps[0]), ctx.getString(C0055R.string.f9t1)) 
//Let's get real strings 1st
m2me(ctx, m0dh(m1gs("xwe", "53P"), ps[0]), "6e9a4d130a9b316e9201238844dd5124")
~~~

Since `m1gs` takes two const strings as input we can just copy it to Java file, call it and get output. Doing this we get:

~~~java
m2me(ctx, m0dh("MD5", ps[0]), "6e9a4d130a9b316e9201238844dd5124")
~~~

So now we look at the `m0dh`, it's actually simple function just hashing second input using hash type specified with first input.

So lastly we need to figure out `m2me` function.

~~~java
   private static boolean m2me(Context ctx, String s1, String s2) {
        boolean res = false;
        try {
            res = ((Boolean) s1.getClass().getMethod(m3r(ctx.getString(C0055R.string.f8m1)), new Class[]{Object.class}).invoke(s1, new Object[]{s2})).booleanValue();
            return res;
        } catch (Exception e) {
            ...
        }
    }
~~~

Looks complicated? But actually all this code is just checking if two strings are equal.
We get `String` class, get equals methods on it (`m3r(ctx.getString(C0055R.string.f8m1))` returns equals) and invoke it.

So turns out we just need to break few MD5 hashes and we can get our flag.
For this we can use [crackstation](https://crackstation.net/).

~~~text
t1 = "6e9a4d130a9b316e9201238844dd5124"                peppa 
t2 = "7c51a5e6ea3214af970a86df89793b19"                9876543
t3 = "e5f20324ae520a11a86c7602e29ecbb8"                BAAAM
t4 = "1885eca5a40bc32d5e1bca61fcd308a5"                A1z9
t5 = "da5062d64347e5e020c5419cebd149a2"                3133337
~~~
Our flag: `MOBISEC{peppa-9876543-BAAAM-A1z9-3133337}`

`t6` corresponds to SHA-256 of whole flag, but we don't have to use it for flag finding.

##GoingNative

This time we have apk using native code. We can find `.so` file used in `lib` folder in apk (there are few different versions of same library for different architectures).

In Java code we have only this:

~~~java

class FlagChecker {
    private static native boolean helloFromTheOtherSide(String str, int i);

    FlagChecker() {
    }

    static {
        System.loadLibrary("native-lib");
    }

    public static boolean checkFlag(String str) {
        String[] split = str.split("-");
        if (split.length != 2 || !split[0].startsWith("MOBISEC{") || !split[1].endsWith("}")) {
            return false;
        }
        String replace = split[0].replace("MOBISEC{", "");
        String replace2 = split[1].replace("}", "");
        if (replace2.matches("^[0-9]*$") && replace2.length() == 6) {
            return helloFromTheOtherSide(replace, Integer.parseInt(replace2));
        }
        return false;
    }
~~~

To disassembly lib, I am going to use Ghidra.

~~~c++

uint Java_com_mobisec_gonative_FlagChecker_helloFromTheOtherSide
               (int *env,undefined4 this,undefined4 res1,int res2)

{
  char *__s;
  size_t sVar1;
  int iVar2;
  uint uVar3;
  uint booleanRes;
  int in_GS_OFFSET;
  char local_1e [5];
  undefined local_19;
  int local_18;
  
  local_18 = *(int *)(in_GS_OFFSET + 0x14);
  __s = (char *)(**(code **)(*env + 0x2a4))(env,res1,0);
  sVar1 = strlen(__s);
  //Len of first part of input is 12 and second part is 31337
  if ((sVar1 == 12) && (res2 == 31337)) {
    //First letter is 'n' and last one is 'o'
    if ((*__s == 'n') && (__s[11] == 'o')) {
      strncpy(local_1e,__s + 1,5);
      local_19 = 0;
      //Input from 1 to 5 is equal to "ative"
      iVar2 = strncmp("ative",local_1e,5);
      if (iVar2 != 0) {
        iVar2 = *env;
        goto LAB_00010750;
      }
      //Here we get few more letters
      if ((((__s[9] == '_') && (__s[6] == '_')) && (__s[7] == 'i')) && (__s[8] == 's')) {
        //Last two letters are equal to "so"
        uVar3 = strcmp("so",__s + 10);
        booleanRes = uVar3 & 0xffffff00 | (uint)(uVar3 == 0);
        (**(code **)(*env + 0x2a8))(env,res1,__s);
        goto LAB_0001075b;
      }
    }
    iVar2 = *env;
  }
  else {
    iVar2 = *env;
  }
  ...
}
~~~

Combining all the bits we have gathered we get our flag:
`MOBISEC{native_is_so-031337}`

Pay attention to 0 in second part of input, in Java part we see that length of it has to be 6. This means we have to pad with zeroes.

##Blockchain

This time we again have to do some brute forcing. Let's look at the Java code:

~~~java
    public static boolean checkFlag(String keyStr, String flagStr) throws Exception {
        byte[] digest = hash(keyStr.getBytes());
        byte[] currKey = hash(new byte[]{digest[0], digest[digest.length / 2], digest[digest.length - 1]});
        byte[] currPt = flagStr.getBytes();
        for (int i = 0; i < 10; i++) {
            currPt = encrypt(currPt, currKey);
            currKey = hash(currKey);
        }
        if (toHex(currPt).equals("0eef68c5ef95b67428c178f045e6fc8389b36a67bbbd800148f7c285f938a24e696ee2925e12ecf7c11f35a345a2a142639fe87ab2dd7530b29db87ca71ffda2af558131d7da615b6966fb0360d5823b79c26608772580bf14558e6b7500183ed7dfd41dbb5686ea92111667fd1eff9cec8dc29f0cfe01e092607da9f7c2602f5463a361ce5c83922cb6c3f5b872dcc088eb85df80503c92232bf03feed304d669ddd5ed1992a26674ecf2513ab25c20f95a5db49fdf6167fda3465a74e0418b2ea99eb2673d4c7e1ff7c4921c4e2d7b")) {
            return true;
        }
        return false;
    }

    public static byte[] encrypt(byte[] in, byte[] key) throws Exception {
        Key aesKey = new SecretKeySpec(key, "AES");
        Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(1, aesKey);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
        cipherOutputStream.write(in);
        cipherOutputStream.flush();
        cipherOutputStream.close();
        return outputStream.toByteArray();
    }

    public static byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(in);
        return md.digest();
    }
~~~

First we have to note that key is actually only 3 bytes which is pretty weak.
Also since AES is symmetric key cipher we can just decrypt final result using same key.

So how can we solve it? 
Randomly generate 3 byte sequences, hash them 10 times using MD5 to get 10 keys and decrypt final result using those keys in order from 10 to 1. Once we get results that is just ASCII we (probably) will have our flag.

~~~java
import java.util.ArrayList; 
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;


public class Blockchain {

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] decrypt(byte[] in, byte[] key) throws Exception {
        Key aesKey = new SecretKeySpec(key, "AES");
        Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(Cipher.DECRYPT_MODE, aesKey);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
        cipherOutputStream.write(in);
        cipherOutputStream.flush();
        cipherOutputStream.close();
        return outputStream.toByteArray();
    }

    public static byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(in);
        return md.digest();
    }

    private static void decodeFlag(byte[] key) throws Exception{
        byte[] currPt = hexStringToByteArray("0eef68c5ef95b67428c178f045e6fc8389b36a67bbbd800148f7c285f938a24e696ee2925e12ecf7c11f35a345a2a142639fe87ab2dd7530b29db87ca71ffda2af558131d7da615b6966fb0360d5823b79c26608772580bf14558e6b7500183ed7dfd41dbb5686ea92111667fd1eff9cec8dc29f0cfe01e092607da9f7c2602f5463a361ce5c83922cb6c3f5b872dcc088eb85df80503c92232bf03feed304d669ddd5ed1992a26674ecf2513ab25c20f95a5db49fdf6167fda3465a74e0418b2ea99eb2673d4c7e1ff7c4921c4e2d7b");
        
        byte[] currKey = key;
        
        ArrayList<byte[]> keys = new ArrayList<>();
        
        keys.add(hash(currKey));
        for (int i = 1; i <10; i++) {
            keys.add(hash(keys.get(i-1)));
        }

        for (int i = 0; i < 10; i++) {
            currPt = decrypt(currPt, keys.get(9 - i));
        }
        String res = new String(currPt);
        if (res.matches("\\A\\p{ASCII}*\\z")) {
            System.out.println(res);
        }
    }
    
    public static void main(String[] args) throws Exception{
        for ( int i = -128; i < 128; i++) {
            for ( int j = -128; j < 128; j++) {
                for ( int k = -128; k < 128; k++) {
                    byte[] currKey = new byte[]{(byte)k, (byte)j, (byte)i};
                    decodeFlag(currKey);
                }              
            }
        }
        
        
    }

}
~~~

After some time, we will get our flag:
`MOBISEC{blockchain_failed_to_deliver_once_again}`