## Recon
```
If we add a host to /etc/hosts, RESCAN
```
#### TCP
Initial Scan
`sudo nmap <ip> -sC -sT -sV -p<ports> -oN ~/proving_grounds/<standalone>/<standalone>_TCP_ALL`


Deep Scan
`sudo nmap <ip> -A -p<ports> -oN ~/proving_grounds/<standalone>/<standalone>_TCP_ALL`

#### UDP
Initial Scan
`sudo nmap <ip> -sU --top-ports=100 -oN ~/proving_grounds/<standalone>/<standalone>_UDP`


Deep Scan
`sudo nmap <ip> -sU -A -p<ports> -oN ~/proving_grounds/<standalone>/<standalone>_UDP_ALL`

#### Autorecon
`sudo env "PATH=$PATH" autorecon <ip_address>

#### Nikto
`nikto -host <ip_address>`



## Parking Lot
```
Annotate sensitive files here that we do not have access to, in case we GAIN access later
```

```
Park creds/key/domain info here:
```
## Footprinting
```
1. Unknown Port? Search for it DIRECTLY on HackTricks
2. google '<service> exploits' AND '<service> RCE'
3. Any ports that do not reveal much, redo scan with -A and specify port
4. Redo scan if host added to /etc/hosts
5. Public exploit not working? Verify, then search for others on github
```

#### 80 http
```
# Notes
```

nmap findings 
	-

nikto
	-

Visit website
	-

Wappalyzer
	versions (including name of site)
		-
	searchsploit
		-
	`google "<version> exploits", "<version> rce", etc
		-

Manual Enumeration
	poke around
	-

/robots.txt
	-

/.htaccess `# ALSO via file upload`
	-

/.env
	-

/.git
	-

/api/
	also try /api
	-

login portal
	default creds
		admin:admin
		Admin:Admin
		source config documentation
			-
	sqli
		-
	forgot password abuse
		-
	check KALI local repo
		-
	hydra brute force ([[Cracking]])
		-
	user/cred reuse
		-

sqli
	[Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
	-

directory traversal `# /index.php?view=<file_name>`
	-

file inclusion `# lfi log poisoning`
	-

RFI
	-

file upload
	-

OS Command injection
	-

XXE `# not in scope for OSCP`
	-

Page Source
	Inspect page source
		-
	html2markdown -- `curl -s <target> | html2markdown`
		-

Read php files `# php://filter...`
	`index.php?page=php://filter/resource=<file>
		-
	`index.php?file=php://filter/convert.base64-encode/resource=<file>
		-

Hacktricks
	-

Automated scanning
	wpscan
	git-dumper
	etc...

Weird/out of place pictures
	-

Duplicate webpages `# ie: /old, compare page sources`
	-

Exposed Config files
	-

Found hashes? `# crackstation, john, hashcat...`
	-

Enumerate webpages
[[Feroxbuster]] Standard scan
	-

[[Feroxbuster]] Extension scan (if standard results are insufficient/lacking)
	-

[[Feroxbuster]] Scan manually identified directories
	-

[[Subdomain Fuzzing]] `# 2 wordlists -- Don't forget to add subdomains to /etc/hosts`
	-

Check github documentation for interesting files
	if you get directory redirects from directories found from ferox, try accessing files within anyway by referencing the github documentation of the webapp

Guess directories (last resort)
	Try names we have enumerated
	ie: if hostname = `<name>`, then try `http://<ip>/<name>`




## Foothold
```
Need to compile something? Ideally we are able to compile on target...
	yes: great
	no: search for precompiled online OR compile locally 

Public exploit not working? Verify, then search for others on github
```


## Internal Enumeration
```
# If in container, do FULL enumeration anyway
# Initial Impressions (if any):

```

#### Windows Manual:
hostname
	-

whoami
	-

whoami /priv 
	-

whoami /groups
	-

set
	-

`dir \Users
	-

local users `# net user`
	-
	specific users `# net user <user>`
		-

domain users `# net user /domain
	-
	specific users
		-

net localgroup
	-

net group
	-

systeminfo
	-

network information
	`ipconfig /all
		-
	`route print
		-
	`netstat -ano     # internally exposed ports? chisel! webapps? conf files, LFI + rev shell, etc..` 
		-

installed apps
	32 bit
		-
	64 bit
		-
	`reg query` any interesting software
		-

Running Apps `# Get-Process`
	-

User History `Get-History`
	-
	PSReadline `# (Get-PSReadlineOption).HistorySavePath`
		-

switch user `# also consider runas /user:<domain>\<user> cmd.exe
	`user:user` cred combinations
		-
	credential reuse
		-
	ssh reuse
		-

Services w/ binary path `# Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`
	-

DLL Hijacking `#procmon`
	-

Unquoted Service Paths
	-

Scheduled Tasks  `# schtasks  |  schtasks /query /fo LIST /v  |  Get-ScheduledTask
	-
	Hunt for specific users -- `Get-ScheduledTask | Where-Object -Property Author -match <user> | fl *`
		-
	`Get-ScheduledTask | Select-Object Author,Trigger,Action,TaskName,TaskPath,Source,Principal | fl`
		-
	TaskScheduler -- `#GUI - look at author, trigger, action, etc...`
		-



Manual Enum: `# dir /a /q`
`\directory\we\spawn\in    # and adjacents`
	-
`\Users\<user>\AppData\stuff
	-
`\Users\<user>\<all_files>
	-
`\Users\<users>
	-
`\
	-
`\xampp`
	-


Config Files and information within


Search for specific files `# Use Get-ChildItem premade queries from master checklist`
	kdbx files
		-
	.txt, .ini files
		-
	home dir recursive search for creds/databases
		-
	zip files
		-
	SAM/SYSTEM/SECURITY
		-



#### Linux Manual:
hostname
	-

whoami
	-

id
	-

sudo -V `# is gcc present?`
	-

sudo -l
	-

env
	-

/etc/passwd
	users
		-
	file perms
		-

/etc/shadow
	-

/etc/sudoers
	-

switch user
	`user:user` cred combinations
		-
	credential reuse
		-
	ssh reuse
		-

os/kernel version info `# is gcc present?` [[OSCP Prep/Methodology Notes/PrivEsc/Kernel Exploits|Kernel Exploits]]
	-

system processes `# ps aux`
	-

interfaces `# ip a`
	-

routes `# routel`
	-

ports `# internally exposed ports? chisel! webapps? conf files, LFI + rev shell, etc..
	-

multiple webservers `# check /var/www and check /etc/apache2/sites-enabled`
	NOTE: vhost could share same port but only be accessible from localhost `# ie: port forward`
	-

scheduled tasks `# pspy64 automated, crontab -l `
	-

installed packages `# dpkg -l`
	-

world writable directories `# find / -writable -type d 2>/dev/null`
	-

mounted drives `# cat /etc/fstab, lsblk`
	-

list loaded drivers `# lsmod`
	-

SUID files `# find / -perm -u=s -type f 2>/dev/null`
	-


Manual Enum:
`/directory/we/spawn/in`    `# and adjacent ones`
	-
`/home/<user>
	-
`/home
	-
`/`
	-
`/opt`
	-
`/var`      `# www/, mail/, etc... cred hunting galore`
	-
anything else of interest
	-

Config files and information within:
	-

.db search `# find / -name *.db 2>/dev/null`
	-

.sql search `# find / -name *.sql 2>/dev/null`
	-

#### Automated:
```

```

## Lateral Movement #1
```
NOTE: if using su, specify -l or - to simulate user logon

# Use this section if we switch users
```

sudo -l  `# or whoami /priv...`
	-

env
	-

repeat enumeration process as user -- focus on user specific directories, groups, etc...


## PrivEsc
```
# Be sure to check common vectors first (to ALL users, including root)
	password reuse
	user:user cred combinations
	ssh key reuse

## Try polkit (Pwnkit), especially when attempting kernel exploits github.com/ly4k/PwnKit | /joeammond/CVE-2021-4034 (python version)
```
#### Attempt 1: <>


## Parking Lot
```
# Annotate sensitive files here that we do not have access to, in case we GAIN access later


```


## Lessons Learned