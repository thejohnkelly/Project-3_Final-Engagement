# Blue Team: Summary of Operations

## Table of Contents
- Network Topology
- Description of Targets
- Monitoring the Targets
- Patterns of Traffic & Behavior
- Suggestions for Going Further

### Network Topology

The following machines were identified on the network:
- Azure
  - **Operating System**: Windows 10 Pro
  - **Purpose**: Gateway
  - **IP Address**: 192.168.1.1

- Kali
  - **Operating System**: Kali GNU/Linux Rolling
  - **Purpose**: Used for penetration testing
  - **IP Address**: 192.168.1.90

- ELK
  - **Operating System**: Ubuntu Linux
  - **Purpose**: Holds the Kibana dashboards
  - **IP Address**: 192.168.1.100

- Capstone
  - **Operating System**: Ubuntu Linux
  - **Purpose**: Collects logs using Filebeat and Metricbeat and forwards those logs to the ELK machine
  - **IP Address**: 192.168.1.105

- Target 1
  - **Operating System**: Debian GNU/Linux 8
  - **Purpose**: Exposes a vulnerable WordPress server
  - **IP Address**: 192.168.1.110

![topology](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Network/topology.png)

### Description of Targets

- The target of this attack was: `Target 1` (192.168.1.110).

- Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:

### Monitoring the Targets

This scan identifies the services below as potential points of entry: 
```bash
nmap -sV 192.168.1.110
```

  - Target 1
    - 22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
    - 80/tcp open http Apache httpd 2.4.10 ((Debian))
    - 111/tcp open rpcbind 2-4 (RPC #100000)
    - 139/tcp open netbios-ssn Samba smbd 3.X 4.x (workgroup: WORKGROUP)
    - 445/tcp open netbios-ssn Samba smbd 3.X 4.X (workgroup: WORKGROUP)

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

![watchers](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/watchers_001.png)

#### **Excessive HTTP Errors**
Alert 1 is implemented as follows:
  - **Metric**: Packetbeat
  - **Threshold**: WHEN count() GROUPED OVER top 5 'http.response.status_code' IS ABOVE 400 FOR THE LAST 5 minutes
  - **Vulnerability Mitigated**: Brute force attack
  - **Reliability**: This alert does not generate a  lot of false positives or negatives. This alert is highly reliable.

![Excessive HTTP Errors](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/watcher_005_Excessive-HTTP-Errors.png)

#### **HTTP Request Size Monitor**
Alert 2 is implemented as follows:
  - **Metric**: Packetbeat
  - **Threshold**: WHEN sum() of http.request.bytes OVER all documents IS ABOVE 3500 FOR THE LAST 1 minute
  - **Vulnerability Mitigated**: Possible payload
  - **Reliability**: This alert generates lots of false positives and negatives. This alert has medium reliability.

![HTTP Request Size Monitor](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/watcher_003_HTTP-Request_size_Monitor.png)

#### **CPU Usage Monitor**
Alert 3 is implemented as follows:
  - **Metric**: Metricbeats
  - **Threshold**: WHEN max() OF system.process.cpu.total.pct OVER all documents IS ABOVE 0.5 FOR THE LAST 5 minutes
  - **Vulnerability Mitigated**: Denial of Service (DoS) attack
  - **Reliability**: This alert does not  generate lots of false positives or negatives. The alert is highly reliable.

![CPU Usage Monitor](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/watcher_004_CPU-Usage-Monitor.png)

### Suggestions for Going Further

The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats, identified by the alerts above. In addition to watching for occurrences of such threats, the network should be hardened against them. The Blue Team suggests that IT implement the fixes below to protect the network:

- Vulnerability 1
  - **Patch**: Intall fail2ban with `apt-get install fail2ban`
  - **Why It Works**: Fail2ban scans log files (e.g. /var/log/apache/error_log) and bans IP’s that show malicious signs such as too many password failures, seeking for exploits etc.

- Vulnerability 2
  - **Patch**: Deploy software updates as soon as vulnerabilities have been found.
  - **Why It Works**: TUpdating the software would prevent attacks.

- Vulnerability 3
  - **Patch**: Cron jobs can be used to schedule system updates, making sure the system is secure.
  - **Why It Works**: This would allow employees to continue their jobs without having to worry about updating the systems frequently because cron jobs can be run in the background.
