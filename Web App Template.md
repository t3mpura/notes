
#### webapp
```
# Notes
```

nmap findings
	-

nikto
	-

Visit website
	

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
