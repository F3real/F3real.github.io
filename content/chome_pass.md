Title: Chrome password extractor
Date: 2019-8-31 10:01
Modified: 2019-8-31 10:01
Category: misc
Tags: rust, misc, chrome
Slug: chrome_pass
Authors: F3real
Summary: How to extract passwords from chrome

Recently, I've stumbled across example of chrome password extractor on reddit [(1)](https://www.reddit.com/r/netsec/comments/cvomf4/chrome_password_dumper/). Since original one was written in Python I thought it will be fun to implement similar thing in Rust.

Usually, if we want to show saved password in Chrome we have to insert windows user password. Passwords are stored in SQLite database usually located in:
~~~text
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
~~~

Interestingly, since passwords are encrypted using `Crypt­Protect­Data` Windows function, logged in user can just directly decrypt them using `CryptUnprotectData` function without providing further credentials. Of course, this means that we assume that we have access to PC and there is argument to be made if this is realistic attack scenario since we have access anyway (but it is interesting to know).

After we connect to database we can simply execute: 
~~~sql
SELECT action_url, username_value, password_value FROM logins
~~~
take the extracted passwords and decrypt them.

Many of browsers are based on Chrome and use slightly modifed path and name of database file. Good list of these browsers and names of DB file they use can be found [here](https://github.com/AlessandroZ/LaZagne/blob/master/Windows/lazagne/softwares/browsers/chromium_based.py).

Most interesting part of whole program was how to handle SQLite connection. Original program assumes that Chrome is closed which doesn't make much sense (but does make our program simpler). Problem is that Chrome, when running, acquires lock on database and running any query will result in error.

One simple, but crude, solution is to simply copy database file and try to access copied version. This will work but it does require writing to disk, which is not ideal.

Browsing to SQLite docs, for simpler way I've found:

>immutable=1

>    The immutable query parameter is a boolean that signals to SQLite that the underlying database file is held on read-only media and cannot be modified, even by another process with elevated privileges. SQLite always opens immutable database files read-only and it skips all file locking and change detection on immutable database files. If these query parameter (or the SQLITE_IOCAP_IMMUTABLE bit in xDeviceCharacteristics) asserts that a database file is immutable and that file changes anyhow, then SQLite might return incorrect query results and/or SQLITE_CORRUPT errors. 

this means that if we are using URI to access db, we can just specify immutable=1 and all checks about DB being locked are skipped.

Full source code can be found [here](https://github.com/F3real/ctf_solutions/blob/master/2019/chrome_pass/src/main.rs).

Rust ecosystem has matured quite a bit, tools like `cargo`, `rustfmt` and `clippy` provide really great way to improve your code and manage your project. With `clippy` we can simply run:
~~~text
cargo clippy --all -- -W clippy::all -W clippy::pedantic -W clippy::restriction -W clippy::nursery -D warnings
~~~
to find and fix many common mistakes.