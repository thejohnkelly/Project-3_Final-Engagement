# Network Forensic Analysis Report

## Time Thieves 
You must inspect your traffic capture to answer the following questions:

1. What is the domain name of the users' custom site?
    - Frank-n-Ted-DC.frank-n-ted.com

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_Frank-n-Ted.png">

2. What is the IP address of the Domain Controller (DC) of the AD network?
    - 10.6.12.12

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_FnT-DC-ipaddr.png">

3. What is the name of the malware downloaded to the 10.6.12.203 machine?
    - june11.dll

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_malware-identified.png">

4. Upload the file to [VirusTotal.com](https://www.virustotal.com/gui/). 

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_malware-submitted.png">

5. What kind of malware is this classified as? 
    - Trojan

---

## Vulnerable Windows Machine

1. Find the following information about the infected Windows machine:
    - Host name: Rotterdan-PC
    - IP address: 176.16.4.205
    - MAC address: 00:59:07:b0:63:a4

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_002-01.png">

2. What is the username of the Windows user whose computer is infected?
    - mattijs.devries

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_002-02_Windows-user.png">

3. What are the IP addresses used in the actual infection traffic?
    - 166.62.111.64
    - 172.16.4.205

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_002_03_malicious-ips.png">

4. As a bonus, retrieve the desktop background of the Windows host.
    - fleshy-in-this-2571786.jpg

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_002-04_background.png">

---

## Illegal Downloads

1. Find the following information about the machine with IP address `10.0.0.201`:
    - MAC address: 00:16:17::18:66:c8
    - Windows username: elmer.blanco
    - OS version: Windows NT 10.0 (Windows 10)

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_torrent-identified.png">

2. Which torrent file did the user download?
    - Betty_Boop_Rhythm_on_the_Reservation.avi.torrent

<img src="/Volumes/Media Drive/Cyber/FINAL PROJECT/screen_grabs/Network/wireshark_Windows-user-name.png">