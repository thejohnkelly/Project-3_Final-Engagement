# Network Forensic Analysis Report

## Time Thieves 
You must inspect your traffic capture to answer the following questions:

1. What is the domain name of the users' custom site?
    - Frank-n-Ted-DC.frank-n-ted.com

![Frank-n-Ted](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_time-thieves_domain-name.png)

2. What is the IP address of the Domain Controller (DC) of the AD network?
    - 10.6.12.12

![Frank-n-Ted IP](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_time-thieves_dc-ipaddr.png)

3. What is the name of the malware downloaded to the 10.6.12.203 machine?
    - june11.dll

![malware identified](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_time-thieves_malware-identified.png)

4. Upload the file to [VirusTotal.com](https://www.virustotal.com/gui/). 

![malware submitted](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_time-thieves_malware-submitted.png)

5. What kind of malware is this classified as? 
    - Trojan

---

## Vulnerable Windows Machine

1. Find the following information about the infected Windows machine:
    - Host name: Rotterdan-PC
    - IP address: 176.16.4.205
    - MAC address: 00:59:07:b0:63:a4

![vulnerable machine](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_vuln-win-machines_host-name_ip_mac-addr.png)

2. What is the username of the Windows user whose computer is infected?
    - mattijs.devries

![user name 1](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_vuln-win-machines_user-name.png)

3. What are the IP addresses used in the actual infection traffic?
    - 166.62.111.64
    - 172.16.4.205

![Malicious IPs](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_vuln-win-machines_malicious-ips.png)

4. As a bonus, retrieve the desktop background of the Windows host.
    - fleshy-in-this-2571786.jpg

![background name](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_vuln-win-machines_desktop-background_source.png)
![background image](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_vuln-win-machines_desktop-background_image.png)

---

## Illegal Downloads

1. Find the following information about the machine with IP address `10.0.0.201`:
    - MAC address: 00:16:17::18:66:c8
    - Windows username: elmer.blanco
    - OS version: Windows NT 10.0 (Windows 10)

![user name 2](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_illegal-downloads_user-name.png)

2. Which torrent file did the user download?
    - Betty_Boop_Rhythm_on_the_Reservation.avi.torrent

![torrent identified](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_illegal-downloads_torrent_identified.png)
![torrent image](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/wireshark_illegal-downloads_torrent_Betty-Boop-Frames.png)
