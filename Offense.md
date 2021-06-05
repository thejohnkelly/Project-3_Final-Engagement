# Red Team: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services

Nmap scan results for each machine reveal the below services and OS details:

```bash
$ nmap -sV -O 192.168.1.110
  Nmap scan report for 192.168.1.110
  Host is up (0.00077s latency).
  shown: 995 closed ports
  PORT STATE SERVICE VERSION
  22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
  80/tcp open http Apache httpd 2.4.10 ((Debian))
  111/tcp open rpcbind 2-4 (RPC #100000)
  139/tcp open netbios-ssn Samba smbd 3.X 4.x (workgroup: WORKGROUP)
  445/tcp open netbios-ssn Samba smbd 3.X 4.X (workgroup: WORKGROUP)
  MAC Address: 00:15:50:00:04:10 (Microsoft)
  Device type: general purpose
  Running: Linux 3.X|4.X
  OS CPE: cpe:/o:linux:linux kernel:3 cpe:/o:linux:linux_kernel:4
  OS details: Linux 3.2 - 4.9
  Network Distance: 1 hop
  Service Info: Host: TARGET1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (i host up) scanned in 13.40 seconds
```

This scan identifies the services below as potential points of entry:
- Target 1
  - 22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
  - 80/tcp open http Apache httpd 2.4.10 ((Debian))
  - 111/tcp open rpcbind 2-4 (RPC #100000)
  - 139/tcp open netbios-ssn Samba smbd 3.X 4.x (workgroup: WORKGROUP)
  - 445/tcp open netbios-ssn Samba smbd 3.X 4.X (workgroup: WORKGROUP)


The following vulnerabilities were identified on each target:
- Target 1
  - Poor password management
  - non-essential sudo privileges
  - Critical
  - Vulnerabilities

_TODO: Include vulnerability scan results to prove the identified vulnerabilities._

### Exploitation
_TODO: Fill out the details below. Include screenshots where possible._

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:
- Target 1
  - `flag1.txt`: b9bbcb33e11b8@be759c4e844862482d
    - **Exploit Used**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_
  - `flag2.txt`: fc3fd58dcdad9ab23faca6e9a36e581c
    - **Exploit Used**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_
  - `flag3.txt`: fafcolab56659591e7dccf93122776cd2
    - **Exploit Used**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_
  - `flag4.txt`: 715dea6c055b9fe3337544932f2941ce
    - **Exploit Used**
      - _TODO: Identify the exploit used_
      - _TODO: Include the command run_